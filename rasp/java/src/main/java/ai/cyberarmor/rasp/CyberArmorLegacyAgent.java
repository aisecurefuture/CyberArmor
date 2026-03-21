/*
 * CyberArmor Protect - Java RASP Agent
 * Runtime Application Self-Protection for AI/LLM API calls.
 *
 * Uses java.lang.instrument to intercept HTTP client calls,
 * detect prompt injection, scan for data exfiltration, and enforce policies.
 *
 * Usage: -javaagent:cyberarmor-rasp.jar[=config.properties]
 *
 * Copyright (c) 2026 CyberArmor, Inc. All rights reserved.
 */
package ai.cyberarmor.rasp;

import java.io.*;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.IllegalClassFormatException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.ProtectionDomain;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * CyberArmorLegacyAgent is a Java Instrumentation agent that intercepts outbound HTTP
 * requests to AI/LLM services, enforces DLP policies, detects prompt injection,
 * and reports telemetry asynchronously to the CyberArmor control plane.
 */
public final class CyberArmorLegacyAgent {

    private static final Logger LOG = Logger.getLogger("ai.cyberarmor.rasp");

    // -------------------------------------------------------------------------
    // Configuration
    // -------------------------------------------------------------------------
    private static volatile AgentConfig config = AgentConfig.defaults();
    private static final AtomicBoolean initialized = new AtomicBoolean(false);

    // Telemetry queue (bounded, non-blocking)
    private static final BlockingQueue<TelemetryEvent> telemetryQueue =
            new LinkedBlockingQueue<>(10_000);
    private static ScheduledExecutorService telemetryExecutor;

    // Policy cache (refreshed periodically)
    private static volatile PolicySet activePolicy = PolicySet.defaultPolicy();
    private static ScheduledExecutorService policySyncExecutor;

    // Metrics
    private static final AtomicLong requestsInspected = new AtomicLong(0);
    private static final AtomicLong requestsBlocked = new AtomicLong(0);
    private static final AtomicLong promptInjectionDetections = new AtomicLong(0);
    private static final AtomicLong dlpViolations = new AtomicLong(0);

    // -------------------------------------------------------------------------
    // AI Endpoint patterns
    // -------------------------------------------------------------------------
    private static final List<Pattern> AI_ENDPOINT_PATTERNS = List.of(
            Pattern.compile("api\\.openai\\.com"),
            Pattern.compile("api\\.anthropic\\.com"),
            Pattern.compile(".*\\.openai\\.azure\\.com"),
            Pattern.compile("generativelanguage\\.googleapis\\.com"),
            Pattern.compile("api\\.cohere\\.ai"),
            Pattern.compile("api-inference\\.huggingface\\.co"),
            Pattern.compile("api\\.replicate\\.com"),
            Pattern.compile("api\\.mistral\\.ai"),
            Pattern.compile("api\\.together\\.xyz"),
            Pattern.compile("api\\.fireworks\\.ai"),
            Pattern.compile("bedrock-runtime\\..*\\.amazonaws\\.com"),
            Pattern.compile("aiplatform\\.googleapis\\.com")
    );

    // -------------------------------------------------------------------------
    // Prompt Injection patterns
    // -------------------------------------------------------------------------
    private static final List<Pattern> INJECTION_PATTERNS = List.of(
            Pattern.compile("(?i)ignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions|prompts|rules)"),
            Pattern.compile("(?i)disregard\\s+(all\\s+)?(previous|prior|above|your)\\s+(instructions|prompts|rules|programming)"),
            Pattern.compile("(?i)you\\s+are\\s+now\\s+(a|an|in)\\s+(unrestricted|jailbroken|DAN|evil|new)"),
            Pattern.compile("(?i)\\bDAN\\b.*\\bmode\\b"),
            Pattern.compile("(?i)system\\s*:\\s*you\\s+are"),
            Pattern.compile("(?i)\\[INST\\]|\\[/INST\\]|<<SYS>>|<\\|im_start\\|>"),
            Pattern.compile("(?i)(forget|override|bypass)\\s+(everything|all|your|safety|the)\\s*(rules|instructions|guidelines|filters|restrictions)?"),
            Pattern.compile("(?i)pretend\\s+(you|that|to\\s+be)\\s+(are|have|don't)"),
            Pattern.compile("(?i)act\\s+as\\s+(if|though)\\s+you\\s+(have|are|were)\\s+no\\s+(restrictions|rules|limits)"),
            Pattern.compile("(?i)\\bhack(ing|ed)?\\b.*\\b(prompt|model|system|AI)\\b"),
            Pattern.compile("(?i)reveal\\s+(your|the)\\s+(system\\s+)?(prompt|instructions|rules)"),
            Pattern.compile("(?i)translate\\s+the\\s+(above|previous|following)\\s+to\\s+.{0,20}(base64|hex|rot13|binary)")
    );

    // -------------------------------------------------------------------------
    // DLP Sensitive-data patterns
    // -------------------------------------------------------------------------
    private static final List<DlpPattern> DLP_PATTERNS = List.of(
            new DlpPattern("SSN", Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b")),
            new DlpPattern("CREDIT_CARD", Pattern.compile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\\b")),
            new DlpPattern("EMAIL_ADDRESS", Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b")),
            new DlpPattern("AWS_KEY", Pattern.compile("(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}")),
            new DlpPattern("PRIVATE_KEY", Pattern.compile("-----BEGIN\\s+(RSA|EC|DSA|OPENSSH)?\\s*PRIVATE\\s+KEY-----")),
            new DlpPattern("API_KEY", Pattern.compile("(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\\s*[=:]\\s*['\"]?([a-zA-Z0-9_\\-]{20,})")),
            new DlpPattern("JWT_TOKEN", Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")),
            new DlpPattern("PHONE_US", Pattern.compile("\\b(?:\\+1[-.]?)?\\(?[0-9]{3}\\)?[-. ]?[0-9]{3}[-. ]?[0-9]{4}\\b")),
            new DlpPattern("IBAN", Pattern.compile("\\b[A-Z]{2}\\d{2}[A-Z0-9]{4}\\d{7}([A-Z0-9]?){0,16}\\b"))
    );

    // -------------------------------------------------------------------------
    // Premain Entry Point
    // -------------------------------------------------------------------------

    /**
     * JVM entry point for -javaagent instrumentation.
     *
     * @param agentArgs optional path to configuration properties file
     * @param inst      the JVM Instrumentation handle
     */
    public static void premain(String agentArgs, Instrumentation inst) {
        if (!initialized.compareAndSet(false, true)) {
            LOG.warning("CyberArmor RASP agent already initialized; skipping duplicate premain.");
            return;
        }

        LOG.info("CyberArmor RASP agent initializing...");

        try {
            // Load configuration
            if (agentArgs != null && !agentArgs.isBlank()) {
                config = AgentConfig.fromFile(agentArgs);
            }
            config = AgentConfig.applyEnvironmentOverrides(config);

            setupLogging();
            startTelemetryFlush();
            startPolicySync();

            // Register class-file transformer for bytecode instrumentation
            inst.addTransformer(new CyberArmorTransformer(), inst.isRetransformClassesSupported());

            // Register shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(CyberArmorAgent::shutdown, "cyberarmor-shutdown"));

            LOG.info("CyberArmor RASP agent initialized successfully. Mode: " + config.enforcementMode);
        } catch (Exception ex) {
            LOG.log(Level.SEVERE, "Failed to initialize CyberArmor RASP agent", ex);
        }
    }

    /**
     * Alternate entry for agentmain (attach API).
     */
    public static void agentmain(String agentArgs, Instrumentation inst) {
        premain(agentArgs, inst);
    }

    // -------------------------------------------------------------------------
    // Core inspection API (called from instrumented code or manually)
    // -------------------------------------------------------------------------

    /**
     * Inspects an outbound HTTP request before it is sent. Returns an
     * {@link InspectionResult} indicating whether the request should proceed.
     *
     * @param method  HTTP method (GET, POST, etc.)
     * @param url     target URL string
     * @param headers map of request headers
     * @param body    request body (may be null)
     * @return inspection result with action and optional block reason
     */
    public static InspectionResult inspectRequest(String method, String url,
                                                   Map<String, String> headers,
                                                   byte[] body) {
        requestsInspected.incrementAndGet();

        // Only deep-inspect AI endpoint calls
        if (!isAIEndpoint(url)) {
            return InspectionResult.allow();
        }

        String bodyStr = (body != null) ? new String(body, StandardCharsets.UTF_8) : "";
        List<Finding> findings = new ArrayList<>();

        // 1. Prompt injection detection
        List<String> injections = detectPromptInjection(bodyStr);
        if (!injections.isEmpty()) {
            promptInjectionDetections.incrementAndGet();
            for (String inj : injections) {
                findings.add(new Finding(FindingType.PROMPT_INJECTION, Severity.HIGH,
                        "Prompt injection detected: " + inj, url));
            }
        }

        // 2. DLP scanning on outbound body
        List<DlpMatch> dlpMatches = scanForSensitiveData(bodyStr);
        if (!dlpMatches.isEmpty()) {
            dlpViolations.incrementAndGet();
            for (DlpMatch m : dlpMatches) {
                findings.add(new Finding(FindingType.DLP_VIOLATION, Severity.CRITICAL,
                        "Sensitive data (" + m.patternName + ") found in outbound AI request", url));
            }
        }

        // 3. Policy enforcement
        PolicyAction action = activePolicy.evaluate(findings, url, method);

        // 4. Emit telemetry asynchronously
        emitTelemetry(new TelemetryEvent(
                Instant.now(), "request_inspection", url, method,
                findings, action, requestsInspected.get()
        ));

        if (action == PolicyAction.BLOCK) {
            requestsBlocked.incrementAndGet();
            String reason = findings.stream()
                    .map(f -> f.type + ": " + f.message)
                    .collect(Collectors.joining("; "));
            LOG.warning("BLOCKED request to " + url + " - " + reason);
            return InspectionResult.block(reason);
        }

        if (action == PolicyAction.LOG) {
            LOG.info("LOGGED (monitor-only) findings for " + url);
        }

        return InspectionResult.allow();
    }

    /**
     * Inspects an AI API response body for potential issues such as data leakage
     * or model misbehavior indicators.
     *
     * @param url          the original request URL
     * @param statusCode   the HTTP response status code
     * @param responseBody the response body bytes
     * @return inspection result
     */
    public static InspectionResult inspectResponse(String url, int statusCode, byte[] responseBody) {
        if (!isAIEndpoint(url) || responseBody == null) {
            return InspectionResult.allow();
        }

        String bodyStr = new String(responseBody, StandardCharsets.UTF_8);
        List<Finding> findings = new ArrayList<>();

        // DLP scan on response (detect model leaking sensitive data)
        List<DlpMatch> dlpMatches = scanForSensitiveData(bodyStr);
        if (!dlpMatches.isEmpty()) {
            dlpViolations.incrementAndGet();
            for (DlpMatch m : dlpMatches) {
                findings.add(new Finding(FindingType.DLP_VIOLATION, Severity.HIGH,
                        "Sensitive data (" + m.patternName + ") found in AI response", url));
            }
        }

        // Check for refusal bypass indicators
        if (bodyStr.length() > 10_000 && detectPromptInjection(bodyStr).size() > 0) {
            findings.add(new Finding(FindingType.RESPONSE_ANOMALY, Severity.MEDIUM,
                    "AI response may contain injected instructions", url));
        }

        if (!findings.isEmpty()) {
            emitTelemetry(new TelemetryEvent(
                    Instant.now(), "response_inspection", url, "RESPONSE",
                    findings, PolicyAction.LOG, requestsInspected.get()
            ));
        }

        PolicyAction action = activePolicy.evaluate(findings, url, "RESPONSE");
        if (action == PolicyAction.BLOCK) {
            requestsBlocked.incrementAndGet();
            return InspectionResult.block("Response blocked due to policy violation");
        }

        return InspectionResult.allow();
    }

    // -------------------------------------------------------------------------
    // Detection Logic
    // -------------------------------------------------------------------------

    static boolean isAIEndpoint(String url) {
        if (url == null) return false;
        for (Pattern p : AI_ENDPOINT_PATTERNS) {
            if (p.matcher(url).find()) return true;
        }
        // Also check custom endpoints from config
        for (String custom : config.customAIEndpoints) {
            if (url.contains(custom)) return true;
        }
        return false;
    }

    static List<String> detectPromptInjection(String text) {
        if (text == null || text.isEmpty()) return List.of();
        List<String> detections = new ArrayList<>();
        for (Pattern p : INJECTION_PATTERNS) {
            Matcher m = p.matcher(text);
            if (m.find()) {
                // Report the matched substring (truncated)
                String match = m.group();
                detections.add(match.length() > 120 ? match.substring(0, 120) + "..." : match);
            }
        }
        // Heuristic: unusually high ratio of special chars may indicate encoding attack
        if (text.length() > 100) {
            long specialChars = text.chars()
                    .filter(c -> c == '\\' || c == '{' || c == '}' || c == '<' || c == '>')
                    .count();
            if ((double) specialChars / text.length() > 0.15) {
                detections.add("Suspicious encoding: high special character ratio");
            }
        }
        return detections;
    }

    static List<DlpMatch> scanForSensitiveData(String text) {
        if (text == null || text.isEmpty()) return List.of();
        List<DlpMatch> matches = new ArrayList<>();
        for (DlpPattern dp : DLP_PATTERNS) {
            Matcher m = dp.pattern.matcher(text);
            while (m.find()) {
                String matched = m.group();
                // Redact all but last 4 characters for logging
                String redacted = "***" + (matched.length() > 4 ? matched.substring(matched.length() - 4) : matched);
                matches.add(new DlpMatch(dp.name, redacted, m.start()));
            }
        }
        // Check custom DLP patterns from policy
        for (DlpPattern custom : activePolicy.customDlpPatterns) {
            Matcher m = custom.pattern.matcher(text);
            while (m.find()) {
                String matched = m.group();
                String redacted = "***" + (matched.length() > 4 ? matched.substring(matched.length() - 4) : matched);
                matches.add(new DlpMatch(custom.name, redacted, m.start()));
            }
        }
        return matches;
    }

    // -------------------------------------------------------------------------
    // Telemetry
    // -------------------------------------------------------------------------

    private static void emitTelemetry(TelemetryEvent event) {
        if (!telemetryQueue.offer(event)) {
            LOG.fine("Telemetry queue full; dropping event.");
        }
    }

    private static void startTelemetryFlush() {
        telemetryExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "cyberarmor-telemetry");
            t.setDaemon(true);
            return t;
        });
        telemetryExecutor.scheduleWithFixedDelay(
                CyberArmorAgent::flushTelemetry,
                config.telemetryFlushIntervalMs,
                config.telemetryFlushIntervalMs,
                TimeUnit.MILLISECONDS
        );
    }

    private static void flushTelemetry() {
        List<TelemetryEvent> batch = new ArrayList<>();
        telemetryQueue.drainTo(batch, 500);
        if (batch.isEmpty()) return;

        try {
            String payload = buildTelemetryPayload(batch);
            sendToControlPlane("/api/v1/telemetry/events", payload);
        } catch (Exception ex) {
            LOG.log(Level.WARNING, "Failed to flush telemetry", ex);
            // Re-enqueue events that fit
            for (TelemetryEvent evt : batch) {
                telemetryQueue.offer(evt);
            }
        }
    }

    private static String buildTelemetryPayload(List<TelemetryEvent> events) {
        StringBuilder sb = new StringBuilder(4096);
        sb.append("{\"agentId\":\"").append(escapeJson(config.agentId)).append("\",");
        sb.append("\"agentVersion\":\"1.0.0\",");
        sb.append("\"timestamp\":\"").append(Instant.now().toString()).append("\",");
        sb.append("\"metrics\":{");
        sb.append("\"requestsInspected\":").append(requestsInspected.get()).append(",");
        sb.append("\"requestsBlocked\":").append(requestsBlocked.get()).append(",");
        sb.append("\"promptInjectionDetections\":").append(promptInjectionDetections.get()).append(",");
        sb.append("\"dlpViolations\":").append(dlpViolations.get());
        sb.append("},\"events\":[");
        for (int i = 0; i < events.size(); i++) {
            if (i > 0) sb.append(",");
            TelemetryEvent e = events.get(i);
            sb.append("{\"timestamp\":\"").append(e.timestamp.toString()).append("\",");
            sb.append("\"type\":\"").append(escapeJson(e.type)).append("\",");
            sb.append("\"url\":\"").append(escapeJson(e.url)).append("\",");
            sb.append("\"method\":\"").append(escapeJson(e.method)).append("\",");
            sb.append("\"action\":\"").append(e.action.name()).append("\",");
            sb.append("\"findingsCount\":").append(e.findings.size());
            sb.append("}");
        }
        sb.append("]}");
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // Policy Sync
    // -------------------------------------------------------------------------

    private static void startPolicySync() {
        policySyncExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "cyberarmor-policy-sync");
            t.setDaemon(true);
            return t;
        });
        policySyncExecutor.scheduleWithFixedDelay(
                CyberArmorAgent::syncPolicies,
                0,
                config.policySyncIntervalMs,
                TimeUnit.MILLISECONDS
        );
    }

    private static void syncPolicies() {
        try {
            String response = fetchFromControlPlane("/api/v1/policies/active");
            if (response != null && !response.isBlank()) {
                PolicySet newPolicy = PolicySet.parse(response);
                if (newPolicy != null) {
                    activePolicy = newPolicy;
                    LOG.fine("Policy set refreshed successfully.");
                }
            }
        } catch (Exception ex) {
            LOG.log(Level.WARNING, "Policy sync failed; continuing with cached policy", ex);
        }
    }

    // -------------------------------------------------------------------------
    // HTTP helpers (minimal, no external dependencies)
    // -------------------------------------------------------------------------

    private static void sendToControlPlane(String path, String jsonPayload) throws IOException {
        URL url = new URL(config.controlPlaneUrl + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + config.apiKey);
            conn.setRequestProperty("X-Agent-Id", config.agentId);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(10000);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonPayload.getBytes(StandardCharsets.UTF_8));
            }

            int status = conn.getResponseCode();
            if (status >= 400) {
                LOG.warning("Control plane returned HTTP " + status + " for " + path);
            }
        } finally {
            conn.disconnect();
        }
    }

    private static String fetchFromControlPlane(String path) throws IOException {
        URL url = new URL(config.controlPlaneUrl + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer " + config.apiKey);
            conn.setRequestProperty("X-Agent-Id", config.agentId);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(10000);

            int status = conn.getResponseCode();
            if (status != 200) {
                LOG.warning("Control plane returned HTTP " + status + " for " + path);
                return null;
            }

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                return reader.lines().collect(Collectors.joining("\n"));
            }
        } finally {
            conn.disconnect();
        }
    }

    // -------------------------------------------------------------------------
    // Shutdown
    // -------------------------------------------------------------------------

    private static void shutdown() {
        LOG.info("CyberArmor RASP agent shutting down...");
        flushTelemetry();
        if (telemetryExecutor != null) telemetryExecutor.shutdownNow();
        if (policySyncExecutor != null) policySyncExecutor.shutdownNow();
        LOG.info("CyberArmor RASP agent shutdown complete. Stats: " +
                "inspected=" + requestsInspected.get() +
                " blocked=" + requestsBlocked.get() +
                " injections=" + promptInjectionDetections.get() +
                " dlp=" + dlpViolations.get());
    }

    // -------------------------------------------------------------------------
    // Bytecode Transformer (instruments HTTP client classes)
    // -------------------------------------------------------------------------

    static final class CyberArmorTransformer implements ClassFileTransformer {

        private static final Set<String> TARGET_CLASSES = Set.of(
                "java/net/HttpURLConnection",
                "sun/net/www/protocol/https/HttpsURLConnectionImpl",
                "sun/net/www/protocol/http/HttpURLConnectionImpl",
                "okhttp3/internal/connection/RealCall",
                "okhttp3/RealCall",
                "org/apache/http/impl/client/CloseableHttpClient",
                "org/apache/http/impl/client/InternalHttpClient"
        );

        @Override
        public byte[] transform(ClassLoader loader, String className,
                                Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain,
                                byte[] classfileBuffer) throws IllegalClassFormatException {
            if (className == null) return null;

            if (TARGET_CLASSES.contains(className)) {
                LOG.fine("CyberArmor intercepting class: " + className);
                // In production, this would use ASM or ByteBuddy to inject
                // inspection calls before actual HTTP send. For now, we rely on
                // the HttpClient wrapping approach below.
                //
                // The agent registers itself so that wrapper/proxy approaches
                // in the CyberArmorHttpInterceptor can find it.
            }
            return null; // return null = no transformation
        }
    }

    // -------------------------------------------------------------------------
    // Logging setup
    // -------------------------------------------------------------------------

    private static void setupLogging() {
        Logger rootLogger = Logger.getLogger("ai.cyberarmor");
        rootLogger.setLevel(config.logLevel);

        // Console handler
        if (rootLogger.getHandlers().length == 0) {
            ConsoleHandler ch = new ConsoleHandler();
            ch.setLevel(config.logLevel);
            ch.setFormatter(new SimpleFormatter());
            rootLogger.addHandler(ch);
        }

        // File handler (optional)
        if (config.logFilePath != null && !config.logFilePath.isBlank()) {
            try {
                FileHandler fh = new FileHandler(config.logFilePath, 10_000_000, 5, true);
                fh.setFormatter(new SimpleFormatter());
                fh.setLevel(config.logLevel);
                rootLogger.addHandler(fh);
            } catch (IOException ex) {
                LOG.warning("Could not create log file: " + ex.getMessage());
            }
        }
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // =========================================================================
    // Inner data classes
    // =========================================================================

    /** Result of a request/response inspection. */
    public static final class InspectionResult {
        public final boolean allowed;
        public final String blockReason;

        private InspectionResult(boolean allowed, String blockReason) {
            this.allowed = allowed;
            this.blockReason = blockReason;
        }

        public static InspectionResult allow() {
            return new InspectionResult(true, null);
        }

        public static InspectionResult block(String reason) {
            return new InspectionResult(false, reason);
        }
    }

    /** Types of security findings. */
    public enum FindingType {
        PROMPT_INJECTION,
        DLP_VIOLATION,
        POLICY_VIOLATION,
        RESPONSE_ANOMALY,
        RATE_LIMIT_EXCEEDED
    }

    /** Severity levels for findings. */
    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    /** Policy enforcement actions. */
    public enum PolicyAction {
        ALLOW, LOG, BLOCK
    }

    /** Enforcement modes. */
    public enum EnforcementMode {
        MONITOR,  // Log-only, never block
        ENFORCE,  // Block on policy violations
        DISABLED  // Agent present but inactive
    }

    /** A single security finding. */
    static final class Finding {
        final FindingType type;
        final Severity severity;
        final String message;
        final String url;

        Finding(FindingType type, Severity severity, String message, String url) {
            this.type = type;
            this.severity = severity;
            this.message = message;
            this.url = url;
        }
    }

    /** A DLP pattern match. */
    static final class DlpMatch {
        final String patternName;
        final String redactedValue;
        final int position;

        DlpMatch(String patternName, String redactedValue, int position) {
            this.patternName = patternName;
            this.redactedValue = redactedValue;
            this.position = position;
        }
    }

    /** Named DLP pattern. */
    static final class DlpPattern {
        final String name;
        final Pattern pattern;

        DlpPattern(String name, Pattern pattern) {
            this.name = name;
            this.pattern = pattern;
        }
    }

    /** A telemetry event. */
    static final class TelemetryEvent {
        final Instant timestamp;
        final String type;
        final String url;
        final String method;
        final List<Finding> findings;
        final PolicyAction action;
        final long requestCount;

        TelemetryEvent(Instant timestamp, String type, String url, String method,
                       List<Finding> findings, PolicyAction action, long requestCount) {
            this.timestamp = timestamp;
            this.type = type;
            this.url = url;
            this.method = method;
            this.findings = findings;
            this.action = action;
            this.requestCount = requestCount;
        }
    }

    // =========================================================================
    // Policy Engine
    // =========================================================================

    static final class PolicySet {
        final EnforcementMode mode;
        final Set<String> blockedEndpoints;
        final Set<String> allowedEndpoints;
        final boolean blockOnPromptInjection;
        final boolean blockOnDlpViolation;
        final Severity minimumBlockSeverity;
        final List<DlpPattern> customDlpPatterns;

        PolicySet(EnforcementMode mode, Set<String> blockedEndpoints,
                  Set<String> allowedEndpoints, boolean blockOnPromptInjection,
                  boolean blockOnDlpViolation, Severity minimumBlockSeverity,
                  List<DlpPattern> customDlpPatterns) {
            this.mode = mode;
            this.blockedEndpoints = blockedEndpoints;
            this.allowedEndpoints = allowedEndpoints;
            this.blockOnPromptInjection = blockOnPromptInjection;
            this.blockOnDlpViolation = blockOnDlpViolation;
            this.minimumBlockSeverity = minimumBlockSeverity;
            this.customDlpPatterns = customDlpPatterns;
        }

        static PolicySet defaultPolicy() {
            return new PolicySet(
                    EnforcementMode.MONITOR,
                    Set.of(),
                    Set.of(),
                    true,
                    true,
                    Severity.HIGH,
                    List.of()
            );
        }

        PolicyAction evaluate(List<Finding> findings, String url, String method) {
            if (mode == EnforcementMode.DISABLED) return PolicyAction.ALLOW;

            // Check explicit endpoint blocks
            for (String blocked : blockedEndpoints) {
                if (url != null && url.contains(blocked)) {
                    return mode == EnforcementMode.ENFORCE ? PolicyAction.BLOCK : PolicyAction.LOG;
                }
            }

            if (findings.isEmpty()) return PolicyAction.ALLOW;

            boolean hasBlockableFindings = false;
            for (Finding f : findings) {
                if (f.severity.ordinal() >= minimumBlockSeverity.ordinal()) {
                    if ((f.type == FindingType.PROMPT_INJECTION && blockOnPromptInjection) ||
                        (f.type == FindingType.DLP_VIOLATION && blockOnDlpViolation)) {
                        hasBlockableFindings = true;
                        break;
                    }
                }
            }

            if (hasBlockableFindings) {
                return mode == EnforcementMode.ENFORCE ? PolicyAction.BLOCK : PolicyAction.LOG;
            }

            return findings.isEmpty() ? PolicyAction.ALLOW : PolicyAction.LOG;
        }

        /** Parse policy JSON from control plane (simplified parser). */
        static PolicySet parse(String json) {
            // In production, use a proper JSON library (Jackson/Gson).
            // This is a minimal fallback parser for boot-time when deps may not be loaded.
            try {
                EnforcementMode mode = EnforcementMode.MONITOR;
                if (json.contains("\"mode\":\"enforce\"") || json.contains("\"mode\": \"enforce\"")) {
                    mode = EnforcementMode.ENFORCE;
                } else if (json.contains("\"mode\":\"disabled\"") || json.contains("\"mode\": \"disabled\"")) {
                    mode = EnforcementMode.DISABLED;
                }

                boolean blockInjection = !json.contains("\"blockOnPromptInjection\":false")
                        && !json.contains("\"blockOnPromptInjection\": false");
                boolean blockDlp = !json.contains("\"blockOnDlpViolation\":false")
                        && !json.contains("\"blockOnDlpViolation\": false");

                return new PolicySet(mode, Set.of(), Set.of(), blockInjection, blockDlp,
                        Severity.HIGH, List.of());
            } catch (Exception ex) {
                LOG.warning("Failed to parse policy JSON; using defaults.");
                return defaultPolicy();
            }
        }
    }

    // =========================================================================
    // Agent Configuration
    // =========================================================================

    static final class AgentConfig {
        final String controlPlaneUrl;
        final String apiKey;
        final String agentId;
        final EnforcementMode enforcementMode;
        final long telemetryFlushIntervalMs;
        final long policySyncIntervalMs;
        final Level logLevel;
        final String logFilePath;
        final List<String> customAIEndpoints;

        AgentConfig(String controlPlaneUrl, String apiKey, String agentId,
                    EnforcementMode enforcementMode, long telemetryFlushIntervalMs,
                    long policySyncIntervalMs, Level logLevel, String logFilePath,
                    List<String> customAIEndpoints) {
            this.controlPlaneUrl = controlPlaneUrl;
            this.apiKey = apiKey;
            this.agentId = agentId;
            this.enforcementMode = enforcementMode;
            this.telemetryFlushIntervalMs = telemetryFlushIntervalMs;
            this.policySyncIntervalMs = policySyncIntervalMs;
            this.logLevel = logLevel;
            this.logFilePath = logFilePath;
            this.customAIEndpoints = customAIEndpoints;
        }

        static AgentConfig defaults() {
            return new AgentConfig(
                    "https://api.cyberarmor.ai",
                    "",
                    UUID.randomUUID().toString(),
                    EnforcementMode.MONITOR,
                    5000,
                    60000,
                    Level.INFO,
                    null,
                    List.of()
            );
        }

        static AgentConfig fromFile(String path) {
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(path)) {
                props.load(fis);
            } catch (IOException ex) {
                LOG.warning("Could not load config from " + path + ": " + ex.getMessage());
                return defaults();
            }
            return fromProperties(props);
        }

        static AgentConfig fromProperties(Properties props) {
            String url = props.getProperty("cyberarmor.controlPlane.url", "https://api.cyberarmor.ai");
            String key = props.getProperty("cyberarmor.apiKey", "");
            String id = props.getProperty("cyberarmor.agentId", UUID.randomUUID().toString());
            EnforcementMode mode;
            try {
                mode = EnforcementMode.valueOf(
                        props.getProperty("cyberarmor.mode", "MONITOR").toUpperCase());
            } catch (IllegalArgumentException e) {
                mode = EnforcementMode.MONITOR;
            }
            long telemetryInterval = Long.parseLong(
                    props.getProperty("cyberarmor.telemetry.flushIntervalMs", "5000"));
            long policyInterval = Long.parseLong(
                    props.getProperty("cyberarmor.policy.syncIntervalMs", "60000"));
            Level level;
            try {
                level = Level.parse(props.getProperty("cyberarmor.logLevel", "INFO"));
            } catch (IllegalArgumentException e) {
                level = Level.INFO;
            }
            String logFile = props.getProperty("cyberarmor.logFile", null);
            String customEndpoints = props.getProperty("cyberarmor.customEndpoints", "");
            List<String> endpoints = customEndpoints.isBlank()
                    ? List.of()
                    : Arrays.asList(customEndpoints.split(","));

            return new AgentConfig(url, key, id, mode, telemetryInterval, policyInterval,
                    level, logFile, endpoints);
        }

        static AgentConfig applyEnvironmentOverrides(AgentConfig base) {
            String envUrl = System.getenv("CYBERARMOR_CONTROL_PLANE_URL");
            String envKey = System.getenv("CYBERARMOR_API_KEY");
            String envMode = System.getenv("CYBERARMOR_MODE");
            String envId = System.getenv("CYBERARMOR_AGENT_ID");

            return new AgentConfig(
                    envUrl != null ? envUrl : base.controlPlaneUrl,
                    envKey != null ? envKey : base.apiKey,
                    envId != null ? envId : base.agentId,
                    envMode != null ? EnforcementMode.valueOf(envMode.toUpperCase()) : base.enforcementMode,
                    base.telemetryFlushIntervalMs,
                    base.policySyncIntervalMs,
                    base.logLevel,
                    base.logFilePath,
                    base.customAIEndpoints
            );
        }
    }

    // =========================================================================
    // OkHttp Interceptor (drop-in for apps using OkHttp)
    // =========================================================================

    /**
     * OkHttp Interceptor that can be added to an OkHttpClient.Builder:
     * <pre>
     *   OkHttpClient client = new OkHttpClient.Builder()
     *       .addInterceptor(CyberArmorAgent.okHttpInterceptor())
     *       .build();
     * </pre>
     *
     * Returns a generic Object to avoid compile-time dependency on OkHttp.
     * At runtime it implements okhttp3.Interceptor via reflection.
     */
    public static Object okHttpInterceptor() {
        return java.lang.reflect.Proxy.newProxyInstance(
                CyberArmorAgent.class.getClassLoader(),
                new Class[]{loadClass("okhttp3.Interceptor")},
                (proxy, method, args) -> {
                    if ("intercept".equals(method.getName())) {
                        return handleOkHttpIntercept(args[0]);
                    }
                    return method.invoke(proxy, args);
                }
        );
    }

    private static Object handleOkHttpIntercept(Object chain) throws Exception {
        // chain.request()
        Object request = chain.getClass().getMethod("request").invoke(chain);

        // Extract URL, method, body
        Object urlObj = request.getClass().getMethod("url").invoke(request);
        String url = urlObj.toString();
        String httpMethod = (String) request.getClass().getMethod("method").invoke(request);

        byte[] bodyBytes = null;
        Object body = request.getClass().getMethod("body").invoke(request);
        if (body != null) {
            Object buffer = loadClass("okio.Buffer").getDeclaredConstructor().newInstance();
            body.getClass().getMethod("writeTo", loadClass("okio.BufferedSink")).invoke(body, buffer);
            bodyBytes = (byte[]) buffer.getClass().getMethod("readByteArray").invoke(buffer);
        }

        // Inspect
        InspectionResult result = inspectRequest(httpMethod, url, Map.of(), bodyBytes);
        if (!result.allowed) {
            // Build a 403 response
            Object responseBuilder = loadClass("okhttp3.Response$Builder")
                    .getDeclaredConstructor().newInstance();
            // Simplified: in production, construct a proper OkHttp Response
            throw new SecurityException("CyberArmor RASP blocked request: " + result.blockReason);
        }

        // Proceed with the original chain
        return chain.getClass().getMethod("proceed", loadClass("okhttp3.Request"))
                .invoke(chain, request);
    }

    private static Class<?> loadClass(String name) {
        try {
            return Class.forName(name);
        } catch (ClassNotFoundException ex) {
            throw new RuntimeException("Required class not found: " + name, ex);
        }
    }

    // =========================================================================
    // HttpURLConnection wrapper
    // =========================================================================

    /**
     * Wraps a standard {@link HttpURLConnection} with CyberArmor inspection.
     * Usage:
     * <pre>
     *   HttpURLConnection conn = (HttpURLConnection) url.openConnection();
     *   conn = CyberArmorAgent.wrapConnection(conn);
     *   // proceed as normal
     * </pre>
     */
    public static HttpURLConnection wrapConnection(HttpURLConnection conn) {
        return new InspectedHttpURLConnection(conn);
    }

    private static final class InspectedHttpURLConnection extends HttpURLConnection {
        private final HttpURLConnection delegate;
        private ByteArrayOutputStream capturedOutput;

        InspectedHttpURLConnection(HttpURLConnection delegate) {
            super(delegate.getURL());
            this.delegate = delegate;
        }

        @Override
        public OutputStream getOutputStream() throws IOException {
            capturedOutput = new ByteArrayOutputStream();
            OutputStream original = delegate.getOutputStream();
            return new FilterOutputStream(original) {
                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    capturedOutput.write(b, off, len);
                    super.write(b, off, len);
                }

                @Override
                public void close() throws IOException {
                    // Inspect before the stream fully closes the connection
                    byte[] body = capturedOutput.toByteArray();
                    InspectionResult result = inspectRequest(
                            delegate.getRequestMethod(),
                            delegate.getURL().toString(),
                            Map.of(),
                            body
                    );
                    if (!result.allowed) {
                        throw new IOException("CyberArmor RASP blocked request: " + result.blockReason);
                    }
                    super.close();
                }
            };
        }

        @Override public void disconnect() { delegate.disconnect(); }
        @Override public boolean usingProxy() { return delegate.usingProxy(); }
        @Override public void connect() throws IOException { delegate.connect(); }
        @Override public InputStream getInputStream() throws IOException { return delegate.getInputStream(); }
        @Override public int getResponseCode() throws IOException { return delegate.getResponseCode(); }
        @Override public String getResponseMessage() throws IOException { return delegate.getResponseMessage(); }
        @Override public void setRequestMethod(String method) throws ProtocolException { delegate.setRequestMethod(method); }
        @Override public String getRequestMethod() { return delegate.getRequestMethod(); }
        @Override public void setRequestProperty(String key, String value) { delegate.setRequestProperty(key, value); }
        @Override public String getHeaderField(String name) { return delegate.getHeaderField(name); }
        @Override public Map<String, List<String>> getHeaderFields() { return delegate.getHeaderFields(); }
        @Override public void setDoOutput(boolean doOutput) { delegate.setDoOutput(doOutput); }
        @Override public void setDoInput(boolean doInput) { delegate.setDoInput(doInput); }
        @Override public void setConnectTimeout(int timeout) { delegate.setConnectTimeout(timeout); }
        @Override public void setReadTimeout(int timeout) { delegate.setReadTimeout(timeout); }
    }
}
