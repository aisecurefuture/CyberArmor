package ai.cyberarmor.providers;

import ai.cyberarmor.CyberArmorClient;
import ai.cyberarmor.audit.AuditEmitter;
import ai.cyberarmor.policy.Decision;
import ai.cyberarmor.policy.PolicyEnforcer;
import ai.cyberarmor.policy.PolicyViolationException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * CyberArmorOpenAI — a drop-in wrapper around the OpenAI Chat Completions API
 * that enforces CyberArmor policy before every request and emits an immutable
 * audit event after every response.
 *
 * <p>Usage:
 * <pre>{@code
 * CyberArmorClient ca = CyberArmorClient.fromEnvironment();
 * CyberArmorOpenAI openai = new CyberArmorOpenAI(ca, System.getenv("OPENAI_API_KEY"));
 *
 * JsonNode response = openai.chatCompletions(
 *     "gpt-4o",
 *     List.of(Map.of("role", "user", "content", "Hello!")),
 *     Map.of("max_tokens", 100)
 * );
 * }</pre>
 */
public class CyberArmorOpenAI {

    private static final Logger log = LoggerFactory.getLogger(CyberArmorOpenAI.class);
    private static final String OPENAI_BASE_URL = "https://api.openai.com/v1";
    private static final String PROVIDER_ID = "openai";

    private final CyberArmorClient cyberArmorClient;
    private final String apiKey;
    private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper mapper;

    /**
     * Create a CyberArmorOpenAI wrapper.
     *
     * @param cyberArmorClient configured CyberArmor client
     * @param apiKey           OpenAI API key (sk-...)
     */
    public CyberArmorOpenAI(CyberArmorClient cyberArmorClient, String apiKey) {
        this(cyberArmorClient, apiKey, OPENAI_BASE_URL);
    }

    /**
     * Create with a custom base URL (e.g. for Azure OpenAI or local proxies).
     */
    public CyberArmorOpenAI(CyberArmorClient cyberArmorClient, String apiKey, String baseUrl) {
        this.cyberArmorClient = cyberArmorClient;
        this.apiKey = apiKey;
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();
        this.mapper = new ObjectMapper();
    }

    /**
     * Call the OpenAI Chat Completions endpoint, protected by CyberArmor policy.
     *
     * @param model      model name, e.g. "gpt-4o"
     * @param messages   list of message maps with "role" and "content"
     * @param extraParams additional parameters (max_tokens, temperature, etc.)
     * @return parsed JSON response from OpenAI
     * @throws PolicyViolationException if CyberArmor policy denies the request
     * @throws IOException              on HTTP errors
     */
    public JsonNode chatCompletions(String model, List<Map<String, Object>> messages,
                                    Map<String, Object> extraParams)
            throws IOException, PolicyViolationException {

        // 1. Extract prompt text for policy evaluation
        String promptText = extractPromptText(messages);
        String tenantId = cyberArmorClient.getConfig().getTenantId();

        // 2. Policy check
        long policyStart = System.currentTimeMillis();
        Decision decision;
        try {
            decision = cyberArmorClient.evaluatePolicy(
                PolicyEnforcer.Options.builder()
                    .action("llm.chat_completions")
                    .provider(PROVIDER_ID)
                    .model(model)
                    .promptText(promptText)
                    .tenantId(tenantId)
                    .build()
            );
        } catch (Exception e) {
            if (cyberArmorClient.getConfig().isFailOpen()) {
                log.warn("[CyberArmor] Policy check failed, failing open: {}", e.getMessage());
                decision = Decision.allowDefault();
            } else {
                throw new IOException("CyberArmor policy check failed: " + e.getMessage(), e);
            }
        }
        long policyMs = System.currentTimeMillis() - policyStart;

        if (!decision.isAllowed()) {
            emitBlockedAuditEvent(model, promptText, decision, tenantId);
            throw new PolicyViolationException(decision);
        }

        // Use redacted prompt if policy requires it
        List<Map<String, Object>> effectiveMessages = messages;
        if (decision.getRedactedPrompt() != null) {
            effectiveMessages = injectRedactedPrompt(messages, decision.getRedactedPrompt());
        }

        // 3. Build OpenAI request body
        ObjectNode body = mapper.createObjectNode();
        body.put("model", model);
        ArrayNode messagesNode = body.putArray("messages");
        for (Map<String, Object> msg : effectiveMessages) {
            ObjectNode msgNode = messagesNode.addObject();
            msg.forEach((k, v) -> msgNode.put(k, String.valueOf(v)));
        }
        if (extraParams != null) {
            extraParams.forEach((k, v) -> {
                if (v instanceof Integer) body.put(k, (Integer) v);
                else if (v instanceof Double) body.put(k, (Double) v);
                else if (v instanceof Boolean) body.put(k, (Boolean) v);
                else body.put(k, String.valueOf(v));
            });
        }

        // 4. Execute HTTP request
        long apiStart = System.currentTimeMillis();
        String responseBody;
        int statusCode;
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/chat/completions"))
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .header("User-Agent", "CyberArmor-Java-SDK/2.0.0")
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                .timeout(Duration.ofSeconds(120))
                .build();

            HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());
            statusCode = response.statusCode();
            responseBody = response.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("OpenAI request interrupted", e);
        }
        long apiMs = System.currentTimeMillis() - apiStart;

        if (statusCode >= 400) {
            throw new IOException(String.format(
                "OpenAI API error %d: %s", statusCode, responseBody));
        }

        JsonNode result = mapper.readTree(responseBody);

        // 5. Emit audit event
        emitSuccessAuditEvent(model, promptText, result, tenantId, policyMs, apiMs,
            decision.getDecisionType());

        return result;
    }

    // ─── Convenience overloads ───────────────────────────────────────────────

    public JsonNode chatCompletions(String model, List<Map<String, Object>> messages)
            throws IOException, PolicyViolationException {
        return chatCompletions(model, messages, Map.of());
    }

    // ─── Private helpers ─────────────────────────────────────────────────────

    private String extractPromptText(List<Map<String, Object>> messages) {
        StringBuilder sb = new StringBuilder();
        for (Map<String, Object> msg : messages) {
            Object content = msg.get("content");
            if (content != null) {
                sb.append(content).append(" ");
            }
        }
        return sb.toString().trim();
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> injectRedactedPrompt(
            List<Map<String, Object>> messages, String redactedPrompt) {
        // Replace the last user message content with the redacted version
        List<Map<String, Object>> copy = new java.util.ArrayList<>(messages);
        for (int i = copy.size() - 1; i >= 0; i--) {
            Map<String, Object> msg = new java.util.LinkedHashMap<>(copy.get(i));
            if ("user".equals(msg.get("role"))) {
                msg.put("content", redactedPrompt);
                copy.set(i, msg);
                break;
            }
        }
        return copy;
    }

    private void emitSuccessAuditEvent(String model, String promptText, JsonNode response,
                                        String tenantId, long policyMs, long apiMs,
                                        String decisionType) {
        try {
            String usage = response.has("usage") ? response.get("usage").toString() : "{}";
            cyberArmorClient.getAuditEmitter().emit(AuditEmitter.Event.builder()
                .eventId(UUID.randomUUID().toString())
                .traceId(UUID.randomUUID().toString())
                .tenantId(tenantId)
                .agentId(cyberArmorClient.getConfig().getAgentId())
                .action("llm.chat_completions")
                .provider(PROVIDER_ID)
                .model(model)
                .promptHash(sha256(promptText))
                .responseHash(response.has("id") ? response.get("id").asText() : "")
                .riskScore(0.0)
                .blocked(false)
                .timestamp(Instant.now().toString())
                .metadata(Map.of(
                    "policy_decision", decisionType,
                    "policy_latency_ms", policyMs,
                    "api_latency_ms", apiMs,
                    "usage", usage
                ))
                .build());
        } catch (Exception e) {
            log.warn("[CyberArmor] Failed to emit audit event: {}", e.getMessage());
        }
    }

    private void emitBlockedAuditEvent(String model, String promptText,
                                        Decision decision, String tenantId) {
        try {
            cyberArmorClient.getAuditEmitter().emit(AuditEmitter.Event.builder()
                .eventId(UUID.randomUUID().toString())
                .traceId(UUID.randomUUID().toString())
                .tenantId(tenantId)
                .agentId(cyberArmorClient.getConfig().getAgentId())
                .action("llm.chat_completions.blocked")
                .provider(PROVIDER_ID)
                .model(model)
                .promptHash(sha256(promptText))
                .riskScore(decision.getRiskScore())
                .blocked(true)
                .timestamp(Instant.now().toString())
                .metadata(Map.of(
                    "policy_decision", decision.getDecisionType(),
                    "reason", decision.getReason() != null ? decision.getReason() : ""
                ))
                .build());
        } catch (Exception e) {
            log.warn("[CyberArmor] Failed to emit blocked audit event: {}", e.getMessage());
        }
    }

    private static String sha256(String input) {
        try {
            var digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            var sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            return "sha256-unavailable";
        }
    }
}
