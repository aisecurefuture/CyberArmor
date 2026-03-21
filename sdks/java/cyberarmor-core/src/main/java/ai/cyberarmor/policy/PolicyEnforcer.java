package ai.cyberarmor.policy;

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
import java.util.concurrent.TimeUnit;

/**
 * PolicyEnforcer handles the evaluation of AI requests against CyberArmor policies.
 *
 * <p>It sends evaluation requests to the control plane's {@code /policies/evaluate}
 * endpoint. If the control plane is unreachable and {@code failOpen} is true,
 * an ALLOW decision is returned. If {@code failOpen} is false, a DENY is returned.
 */
public class PolicyEnforcer implements Closeable {

    private static final Logger log = LoggerFactory.getLogger(PolicyEnforcer.class);

    private static final MediaType JSON_MEDIA_TYPE = MediaType.get("application/json; charset=utf-8");

    private final CyberArmorConfig config;
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;

    public PolicyEnforcer(CyberArmorConfig config) {
        this.config = config;
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(config.getTimeoutMs(), TimeUnit.MILLISECONDS)
                .readTimeout(config.getTimeoutMs(), TimeUnit.MILLISECONDS)
                .writeTimeout(config.getTimeoutMs(), TimeUnit.MILLISECONDS)
                .build();
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    // Allow injection of a custom OkHttpClient (for testing)
    PolicyEnforcer(CyberArmorConfig config, OkHttpClient httpClient) {
        this.config = config;
        this.httpClient = httpClient;
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /**
     * Evaluate a policy for the given options synchronously.
     *
     * @param opts evaluation options
     * @return the policy {@link Decision}
     */
    public Decision evaluate(Options opts) {
        long start = System.currentTimeMillis();
        try {
            Map<String, Object> body = buildRequestBody(opts);
            String json = objectMapper.writeValueAsString(body);

            Request request = new Request.Builder()
                    .url(config.getControlPlaneUrl() + "/policies/evaluate")
                    .addHeader("x-agent-id", config.getAgentId() != null ? config.getAgentId() : "")
                    .addHeader("x-agent-secret", config.getAgentSecret() != null ? config.getAgentSecret() : "")
                    .addHeader("Content-Type", "application/json")
                    .addHeader("Accept", "application/json")
                    .post(RequestBody.create(json, JSON_MEDIA_TYPE))
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                long latency = System.currentTimeMillis() - start;

                if (!response.isSuccessful()) {
                    log.warn("Policy evaluation returned HTTP {}, applying local fallback", response.code());
                    return localFallback(opts, latency);
                }

                ResponseBody responseBody = response.body();
                if (responseBody == null) {
                    log.warn("Policy evaluation returned empty body, applying local fallback");
                    return localFallback(opts, latency);
                }

                String responseJson = responseBody.string();
                Decision decision = objectMapper.readValue(responseJson, Decision.class);
                decision.setLatencyMs(latency);

                log.debug("Policy evaluated in {}ms: type={} reason={} agentId={}",
                        latency, decision.getType(), decision.getReasonCode(), config.getAgentId());

                return decision;
            }
        } catch (IOException e) {
            long latency = System.currentTimeMillis() - start;
            log.warn("Policy evaluation failed (latency={}ms): {} — applying {} fallback",
                    latency, e.getMessage(), config.isFailOpen() ? "fail-open" : "fail-closed");
            return config.isFailOpen()
                    ? Decision.failOpen()
                    : Decision.deny("CONTROL_PLANE_UNREACHABLE");
        } catch (Exception e) {
            long latency = System.currentTimeMillis() - start;
            log.error("Unexpected error during policy evaluation (latency={}ms): {}",
                    latency, e.getMessage(), e);
            return config.isFailOpen()
                    ? Decision.failOpen()
                    : Decision.deny("POLICY_EVALUATOR_ERROR");
        }
    }

    /**
     * Local fallback evaluation applied when the control plane is unreachable.
     *
     * <p>This implements a minimal set of safety checks as a last line of defense:
     * <ul>
     *   <li>Rejects requests with extremely high-risk data classification scores</li>
     *   <li>Otherwise allows based on the failOpen setting</li>
     * </ul>
     */
    private Decision localFallback(Options opts, long latencyMs) {
        // Basic local checks: reject if data classifications include known critical types
        if (opts.getDataClassifications() != null) {
            List<String> critical = Arrays.asList(
                    "PII_SSN", "PII_CREDIT_CARD", "CLASSIFIED", "TOP_SECRET");
            for (String dc : opts.getDataClassifications()) {
                if (critical.contains(dc.toUpperCase())) {
                    Decision deny = Decision.deny("LOCAL_FALLBACK_CRITICAL_DATA_CLASS");
                    deny.setLatencyMs(latencyMs);
                    deny.setExplanation("Local fallback: critical data classification detected");
                    return deny;
                }
            }
        }

        if (config.isFailOpen()) {
            Decision d = Decision.failOpen();
            d.setLatencyMs(latencyMs);
            return d;
        } else {
            Decision d = Decision.deny("CONTROL_PLANE_UNAVAILABLE");
            d.setExplanation("Fail-closed: control plane unavailable");
            d.setLatencyMs(latencyMs);
            return d;
        }
    }

    private Map<String, Object> buildRequestBody(Options opts) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("agent_id", config.getAgentId());
        body.put("tenant_id", opts.getTenantId() != null ? opts.getTenantId() : config.getTenantId());
        body.put("timestamp", Instant.now().toString());
        if (opts.getAction() != null) body.put("action", opts.getAction());
        if (opts.getProvider() != null) body.put("provider", opts.getProvider());
        if (opts.getModel() != null) body.put("model", opts.getModel());
        if (opts.getToolName() != null) body.put("tool_name", opts.getToolName());
        if (opts.getPromptText() != null) body.put("prompt_text", opts.getPromptText());
        if (opts.getDataClassifications() != null) body.put("data_classifications", opts.getDataClassifications());
        if (opts.getSessionId() != null) body.put("session_id", opts.getSessionId());
        if (opts.getUserId() != null) body.put("user_id", opts.getUserId());
        if (opts.getAdditionalContext() != null) body.put("context", opts.getAdditionalContext());
        return body;
    }

    @Override
    public void close() {
        httpClient.dispatcher().executorService().shutdown();
        httpClient.connectionPool().evictAll();
    }

    // -------------------------------------------------------------------------
    // Options inner class
    // -------------------------------------------------------------------------

    /**
     * Options for a policy evaluation request.
     */
    public static class Options {

        /** The action being performed, e.g. "llm.invoke", "tool.call", "memory.read" */
        private String action;

        /** The AI provider, e.g. "openai", "anthropic", "google" */
        private String provider;

        /** The model being used, e.g. "gpt-4o", "claude-3-5-sonnet", "gemini-1.5-pro" */
        private String model;

        /** The tool name if a tool/function is being called */
        private String toolName;

        /** The raw prompt text (will be scanned for PII, injections, etc.) */
        private String promptText;

        /** Optional list of data classification labels present in the context */
        private List<String> dataClassifications;

        /** Optional session identifier for multi-turn conversation tracking */
        private String sessionId;

        /** Optional end-user identifier */
        private String userId;

        /** Optional tenant override */
        private String tenantId;

        /** Optional additional key/value context */
        private Map<String, Object> additionalContext;

        public Options() {
        }

        private Options(Builder builder) {
            this.action = builder.action;
            this.provider = builder.provider;
            this.model = builder.model;
            this.toolName = builder.toolName;
            this.promptText = builder.promptText;
            this.dataClassifications = builder.dataClassifications;
            this.sessionId = builder.sessionId;
            this.userId = builder.userId;
            this.tenantId = builder.tenantId;
            this.additionalContext = builder.additionalContext;
        }

        public static Builder builder() { return new Builder(); }

        public String getAction() { return action; }
        public void setAction(String action) { this.action = action; }
        public String getProvider() { return provider; }
        public void setProvider(String provider) { this.provider = provider; }
        public String getModel() { return model; }
        public void setModel(String model) { this.model = model; }
        public String getToolName() { return toolName; }
        public void setToolName(String toolName) { this.toolName = toolName; }
        public String getPromptText() { return promptText; }
        public void setPromptText(String promptText) { this.promptText = promptText; }
        public List<String> getDataClassifications() { return dataClassifications; }
        public void setDataClassifications(List<String> dataClassifications) { this.dataClassifications = dataClassifications; }
        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public String getTenantId() { return tenantId; }
        public void setTenantId(String tenantId) { this.tenantId = tenantId; }
        public Map<String, Object> getAdditionalContext() { return additionalContext; }
        public void setAdditionalContext(Map<String, Object> additionalContext) { this.additionalContext = additionalContext; }

        public static class Builder {
            private String action;
            private String provider;
            private String model;
            private String toolName;
            private String promptText;
            private List<String> dataClassifications;
            private String sessionId;
            private String userId;
            private String tenantId;
            private Map<String, Object> additionalContext;

            public Builder action(String action) { this.action = action; return this; }
            public Builder provider(String provider) { this.provider = provider; return this; }
            public Builder model(String model) { this.model = model; return this; }
            public Builder toolName(String toolName) { this.toolName = toolName; return this; }
            public Builder promptText(String promptText) { this.promptText = promptText; return this; }
            public Builder dataClassifications(List<String> dc) { this.dataClassifications = dc; return this; }
            public Builder dataClassifications(String... dc) { this.dataClassifications = Arrays.asList(dc); return this; }
            public Builder sessionId(String sessionId) { this.sessionId = sessionId; return this; }
            public Builder userId(String userId) { this.userId = userId; return this; }
            public Builder tenantId(String tenantId) { this.tenantId = tenantId; return this; }
            public Builder additionalContext(Map<String, Object> ctx) { this.additionalContext = ctx; return this; }
            public Builder addContext(String key, Object value) {
                if (this.additionalContext == null) this.additionalContext = new LinkedHashMap<>();
                this.additionalContext.put(key, value);
                return this;
            }
            public Options build() { return new Options(this); }
        }
    }
}
