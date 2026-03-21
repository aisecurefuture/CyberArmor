package ai.cyberarmor.frameworks;

import ai.cyberarmor.CyberArmorClient;
import ai.cyberarmor.policy.Decision;
import ai.cyberarmor.policy.PolicyEnforcer;
import ai.cyberarmor.policy.PolicyViolationException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Generic Vercel-AI-style adapter for Java stacks.
 * Applies CyberArmor policy before generation and emits an audit event after.
 */
public class CyberArmorVercelAIAdapter {

    private final CyberArmorClient client;
    private final String provider;
    private final String model;
    private final String tenantId;

    public CyberArmorVercelAIAdapter(CyberArmorClient client, String provider, String model, String tenantId) {
        this.client = Objects.requireNonNull(client, "client must not be null");
        this.provider = provider != null ? provider : "openai";
        this.model = model != null ? model : "gpt-4o";
        this.tenantId = tenantId != null ? tenantId : client.getConfig().getTenantId();
    }

    public String generate(String input, Function<String, String> delegate) {
        Objects.requireNonNull(delegate, "delegate must not be null");

        Decision decision = client.evaluatePolicy(
                PolicyEnforcer.Options.builder()
                        .action("framework.vercelai.generate")
                        .provider(provider)
                        .model(model)
                        .promptText(input)
                        .tenantId(tenantId)
                        .build()
        );
        if (!decision.isAllowed() && "block".equalsIgnoreCase(client.getConfig().getEnforceMode())) {
            throw new PolicyViolationException(decision);
        }

        long start = System.currentTimeMillis();
        String out = delegate.apply(input);
        long elapsed = System.currentTimeMillis() - start;

        Map<String, Object> audit = new LinkedHashMap<>();
        audit.put("provider", provider);
        audit.put("model", model);
        audit.put("decision_type", decision.getDecisionType());
        audit.put("latency_ms", elapsed);
        client.emitEvent("framework.vercelai.generate", audit);
        return out;
    }
}
