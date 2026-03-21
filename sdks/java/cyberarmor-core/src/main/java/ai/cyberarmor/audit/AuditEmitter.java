package ai.cyberarmor.audit;

import ai.cyberarmor.config.CyberArmorConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * AuditEmitter asynchronously buffers and ships audit events to the CyberArmor
 * control plane's {@code /audit/events/batch} endpoint.
 *
 * <p>Events are buffered in a {@link ConcurrentLinkedQueue}. A
 * {@link ScheduledExecutorService} drains the queue periodically (default every
 * 30 seconds) or when the batch size reaches the configured threshold.
 *
 * <p>Call {@link #flush()} before application shutdown to ensure all buffered
 * events are sent.
 */
public class AuditEmitter implements Closeable {

    private static final Logger log = LoggerFactory.getLogger(AuditEmitter.class);

    private static final MediaType JSON_MEDIA_TYPE = MediaType.get("application/json; charset=utf-8");

    private final CyberArmorConfig config;
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final ConcurrentLinkedQueue<Map<String, Object>> eventQueue;
    private final ScheduledExecutorService scheduler;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    public AuditEmitter(CyberArmorConfig config) {
        this.config = config;
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(config.getTimeoutMs(), TimeUnit.MILLISECONDS)
                .readTimeout(config.getTimeoutMs(), TimeUnit.MILLISECONDS)
                .writeTimeout(config.getTimeoutMs(), TimeUnit.MILLISECONDS)
                .build();
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        this.eventQueue = new ConcurrentLinkedQueue<>();

        // Schedule background flush
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "cyberarmor-audit-flusher");
            t.setDaemon(true);
            return t;
        });
        this.scheduler.scheduleAtFixedRate(
                this::flushIfReady,
                config.getAuditFlushIntervalSeconds(),
                config.getAuditFlushIntervalSeconds(),
                TimeUnit.SECONDS
        );
    }

    // Allow injection for testing
    AuditEmitter(CyberArmorConfig config, OkHttpClient httpClient) {
        this.config = config;
        this.httpClient = httpClient;
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        this.eventQueue = new ConcurrentLinkedQueue<>();
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "cyberarmor-audit-flusher");
            t.setDaemon(true);
            return t;
        });
        this.scheduler.scheduleAtFixedRate(
                this::flushIfReady,
                config.getAuditFlushIntervalSeconds(),
                config.getAuditFlushIntervalSeconds(),
                TimeUnit.SECONDS
        );
    }

    /**
     * Enqueue an audit event. Returns the generated event ID.
     *
     * @param eventType the event type (e.g. "llm.invoke", "policy.deny")
     * @param data      key/value payload
     * @return the generated UUID event ID
     */
    public String emit(String eventType, Map<String, Object> data) {
        if (closed.get()) {
            log.warn("AuditEmitter is closed, dropping event type={}", eventType);
            return "";
        }

        String eventId = UUID.randomUUID().toString();
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("event_id", eventId);
        event.put("event_type", eventType);
        event.put("agent_id", config.getAgentId());
        event.put("tenant_id", config.getTenantId());
        event.put("timestamp", Instant.now().toString());
        if (data != null) {
            event.putAll(data);
        }

        eventQueue.offer(event);
        log.debug("Enqueued audit event type={} eventId={} queueSize={}",
                eventType, eventId, eventQueue.size());

        // Flush immediately if batch size reached
        if (eventQueue.size() >= config.getAuditBatchSize()) {
            scheduler.execute(this::flushNow);
        }

        return eventId;
    }

    public String emit(Event event) {
        if (event == null) return "";
        Map<String, Object> data = new LinkedHashMap<>();
        if (event.traceId != null) data.put("trace_id", event.traceId);
        if (event.tenantId != null) data.put("tenant_id", event.tenantId);
        if (event.agentId != null) data.put("agent_id", event.agentId);
        if (event.provider != null) data.put("provider", event.provider);
        if (event.model != null) data.put("model", event.model);
        if (event.timestamp != null) data.put("timestamp", event.timestamp);
        if (event.metadata != null) data.putAll(event.metadata);
        if (event.blocked != null) data.put("outcome", event.blocked ? "blocked" : "success");
        if (event.riskScore != null) data.put("risk_score", event.riskScore);
        if (event.action != null) data.put("action", event.action);
        if (event.eventId != null) data.put("event_id", event.eventId);
        String eventType = event.action != null ? event.action : "sdk_event";
        return emit(eventType, data);
    }

    /**
     * Flush all buffered events to the control plane synchronously.
     * Blocks until the flush is complete or times out.
     */
    public void flush() {
        try {
            Future<?> future = scheduler.submit(this::flushNow);
            future.get(config.getTimeoutMs() * 2L, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Flush interrupted");
        } catch (ExecutionException e) {
            log.error("Flush execution failed: {}", e.getMessage(), e);
        } catch (TimeoutException e) {
            log.warn("Flush timed out after {}ms", config.getTimeoutMs() * 2L);
        }
    }

    /** Internal: flush if batch threshold is exceeded */
    private void flushIfReady() {
        if (!eventQueue.isEmpty()) {
            flushNow();
        }
    }

    /** Internal: drain queue and send to control plane */
    private void flushNow() {
        List<Map<String, Object>> batch = new ArrayList<>();
        Map<String, Object> event;
        int limit = config.getAuditBatchSize();

        while ((event = eventQueue.poll()) != null && batch.size() < limit) {
            batch.add(event);
        }

        if (batch.isEmpty()) return;

        log.debug("Flushing {} audit events to control plane", batch.size());

        try {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("events", batch);
            body.put("agent_id", config.getAgentId());
            body.put("tenant_id", config.getTenantId());
            body.put("batch_size", batch.size());
            body.put("timestamp", Instant.now().toString());

            String json = objectMapper.writeValueAsString(body);

            Request request = new Request.Builder()
                    .url(config.getControlPlaneUrl() + "/audit/events/batch")
                    .addHeader("x-agent-id", config.getAgentId() != null ? config.getAgentId() : "")
                    .addHeader("x-agent-secret", config.getAgentSecret() != null ? config.getAgentSecret() : "")
                    .addHeader("Content-Type", "application/json")
                    .post(RequestBody.create(json, JSON_MEDIA_TYPE))
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (response.isSuccessful()) {
                    log.debug("Successfully flushed {} audit events", batch.size());
                } else {
                    log.warn("Audit flush returned HTTP {}; {} events may be lost", response.code(), batch.size());
                }
            }
        } catch (IOException e) {
            log.error("Audit flush failed: {} — {} events may be lost", e.getMessage(), batch.size());
            // Re-queue events on failure if queue isn't too large (back-pressure)
            if (eventQueue.size() < config.getAuditBatchSize() * 10) {
                eventQueue.addAll(batch);
                log.debug("Re-queued {} events for retry", batch.size());
            }
        } catch (Exception e) {
            log.error("Unexpected audit flush error: {}", e.getMessage(), e);
        }
    }

    /** @return the number of events currently buffered */
    public int getPendingCount() {
        return eventQueue.size();
    }

    public static final class Event {
        private String eventId;
        private String traceId;
        private String tenantId;
        private String agentId;
        private String action;
        private String provider;
        private String model;
        private String promptHash;
        private String responseHash;
        private Double riskScore;
        private Boolean blocked;
        private String timestamp;
        private Map<String, Object> metadata;

        public static Builder builder() { return new Builder(); }

        public static final class Builder {
            private final Event event = new Event();
            public Builder eventId(String value) { event.eventId = value; return this; }
            public Builder traceId(String value) { event.traceId = value; return this; }
            public Builder tenantId(String value) { event.tenantId = value; return this; }
            public Builder agentId(String value) { event.agentId = value; return this; }
            public Builder action(String value) { event.action = value; return this; }
            public Builder provider(String value) { event.provider = value; return this; }
            public Builder model(String value) { event.model = value; return this; }
            public Builder promptHash(String value) { event.promptHash = value; return this; }
            public Builder responseHash(String value) { event.responseHash = value; return this; }
            public Builder riskScore(Double value) { event.riskScore = value; return this; }
            public Builder blocked(Boolean value) { event.blocked = value; return this; }
            public Builder timestamp(String value) { event.timestamp = value; return this; }
            public Builder metadata(Map<String, Object> value) { event.metadata = value; return this; }
            public Event build() { return event; }
        }
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            log.info("Closing AuditEmitter, flushing {} remaining events", eventQueue.size());
            scheduler.shutdown();
            try {
                flushNow();
                if (!scheduler.awaitTermination(config.getTimeoutMs(), TimeUnit.MILLISECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                scheduler.shutdownNow();
            }
            httpClient.dispatcher().executorService().shutdown();
            httpClient.connectionPool().evictAll();
        }
    }
}
