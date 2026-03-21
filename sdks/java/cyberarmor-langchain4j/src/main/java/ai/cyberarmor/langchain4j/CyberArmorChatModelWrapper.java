package ai.cyberarmor.langchain4j;

import ai.cyberarmor.CyberArmorClient;
import ai.cyberarmor.policy.Decision;
import ai.cyberarmor.policy.PolicyEnforcer;
import ai.cyberarmor.policy.PolicyViolationException;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.model.output.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * CyberArmorChatModelWrapper wraps any {@link ChatLanguageModel} and intercepts
 * every {@code generate()} call to enforce CyberArmor policies before the request
 * is forwarded to the underlying model.
 *
 * <p>Usage:
 * <pre>{@code
 * ChatLanguageModel baseModel = OpenAiChatModel.builder()
 *     .apiKey(System.getenv("OPENAI_API_KEY"))
 *     .modelName("gpt-4o")
 *     .build();
 *
 * CyberArmorClient cyberArmor = CyberArmorClient.builder()
 *     .agentId("my-agent")
 *     .agentSecret("my-secret")
 *     .build();
 *
 * ChatLanguageModel secured = new CyberArmorChatModelWrapper(baseModel, cyberArmor, "openai", "gpt-4o");
 *
 * // Policy enforcement happens automatically
 * Response<AiMessage> response = secured.generate(UserMessage.from("Hello!"));
 * }</pre>
 */
public class CyberArmorChatModelWrapper implements ChatLanguageModel {

    private static final Logger log = LoggerFactory.getLogger(CyberArmorChatModelWrapper.class);

    private final ChatLanguageModel delegate;
    private final CyberArmorClient cyberArmor;
    private final String provider;
    private final String modelName;

    /**
     * Wrap a {@link ChatLanguageModel} with CyberArmor policy enforcement.
     *
     * @param delegate   the underlying model to delegate to after policy passes
     * @param cyberArmor the configured {@link CyberArmorClient}
     * @param provider   the provider name (e.g., "openai", "anthropic", "google")
     * @param modelName  the model name (e.g., "gpt-4o", "claude-3-5-sonnet")
     */
    public CyberArmorChatModelWrapper(ChatLanguageModel delegate,
                                       CyberArmorClient cyberArmor,
                                       String provider,
                                       String modelName) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.cyberArmor = Objects.requireNonNull(cyberArmor, "cyberArmor must not be null");
        this.provider = provider != null ? provider : "unknown";
        this.modelName = modelName != null ? modelName : "unknown";
    }

    /**
     * {@inheritDoc}
     *
     * <p>Before delegating to the underlying model, evaluates the request against
     * CyberArmor policies. Throws {@link PolicyViolationException} if the request
     * is denied and enforcement mode is "block".
     */
    @Override
    public Response<AiMessage> generate(List<ChatMessage> messages) {
        long start = System.currentTimeMillis();

        // Extract prompt text from the messages for policy evaluation
        String promptText = extractPromptText(messages);

        PolicyEnforcer.Options opts = PolicyEnforcer.Options.builder()
                .action("llm.invoke")
                .provider(provider)
                .model(modelName)
                .promptText(promptText)
                .addContext("message_count", messages.size())
                .addContext("has_system_message", hasSystemMessage(messages))
                .build();

        Decision decision = cyberArmor.evaluatePolicy(opts);

        Map<String, Object> auditData = new HashMap<>();
        auditData.put("provider", provider);
        auditData.put("model", modelName);
        auditData.put("decision_type", decision.getType() != null ? decision.getType().getValue() : "UNKNOWN");
        auditData.put("risk_score", decision.getRiskScore());
        auditData.put("policy_id", decision.getPolicyId());
        auditData.put("message_count", messages.size());

        if (!decision.isAllowed()) {
            auditData.put("outcome", "blocked");
            cyberArmor.emitEvent("llm.blocked", auditData);
            log.warn("LLM request blocked by CyberArmor policy: provider={} model={} reason={} riskScore={}",
                    provider, modelName, decision.getReasonCode(), decision.getRiskScore());

            if ("block".equalsIgnoreCase(cyberArmor.getConfig().getEnforceMode())) {
                throw new PolicyViolationException(decision);
            }
            // In monitor mode, log but allow through
            log.info("Monitor mode: allowing blocked request through for provider={} model={}", provider, modelName);
        }

        // Delegate to the underlying model
        try {
            Response<AiMessage> response = delegate.generate(messages);
            long latency = System.currentTimeMillis() - start;
            auditData.put("outcome", "allowed");
            auditData.put("latency_ms", latency);
            cyberArmor.emitEvent("llm.invoke", auditData);
            return response;
        } catch (Exception e) {
            auditData.put("outcome", "error");
            auditData.put("error", e.getMessage());
            cyberArmor.emitEvent("llm.error", auditData);
            throw e;
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private String extractPromptText(List<ChatMessage> messages) {
        return messages.stream()
                .map(m -> {
                    if (m instanceof UserMessage um) {
                        return um.singleText();
                    } else if (m instanceof SystemMessage sm) {
                        return sm.text();
                    } else if (m instanceof AiMessage am) {
                        return am.text();
                    }
                    return m.toString();
                })
                .filter(Objects::nonNull)
                .collect(Collectors.joining("\n"));
    }

    private boolean hasSystemMessage(List<ChatMessage> messages) {
        return messages.stream().anyMatch(m -> m instanceof SystemMessage);
    }

    /** @return the underlying {@link ChatLanguageModel} delegate */
    public ChatLanguageModel getDelegate() { return delegate; }

    /** @return the AI provider name */
    public String getProvider() { return provider; }

    /** @return the model name */
    public String getModelName() { return modelName; }
}
