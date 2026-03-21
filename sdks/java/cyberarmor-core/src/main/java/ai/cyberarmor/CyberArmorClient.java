package ai.cyberarmor;

import ai.cyberarmor.audit.AuditEmitter;
import ai.cyberarmor.config.CyberArmorConfig;
import ai.cyberarmor.policy.Decision;
import ai.cyberarmor.policy.PolicyEnforcer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.util.Map;

/**
 * CyberArmorClient — the primary entry point for the CyberArmor Java SDK.
 *
 * <p>Use the {@link Builder} to configure and construct an instance:
 * <pre>{@code
 * CyberArmorClient client = CyberArmorClient.builder()
 *     .controlPlaneUrl("https://cp.cyberarmor.ai")
 *     .agentId("agent-abc123")
 *     .agentSecret("secret-xyz")
 *     .enforceMode("block")
 *     .build();
 *
 * Decision decision = client.evaluatePolicy(
 *     PolicyEnforcer.Options.builder()
 *         .action("llm.invoke")
 *         .provider("openai")
 *         .model("gpt-4o")
 *         .promptText("Tell me about...")
 *         .build()
 * );
 *
 * if (!decision.isAllowed()) {
 *     throw new PolicyViolationException(decision);
 * }
 * }</pre>
 */
public class CyberArmorClient implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(CyberArmorClient.class);

    private final CyberArmorConfig config;
    private final PolicyEnforcer policyEnforcer;
    private final AuditEmitter auditEmitter;

    private CyberArmorClient(Builder builder) {
        this.config = builder.config;
        this.policyEnforcer = new PolicyEnforcer(config);
        this.auditEmitter = new AuditEmitter(config);
        log.info("CyberArmorClient initialized agentId={} url={} mode={}",
                config.getAgentId(), config.getControlPlaneUrl(), config.getEnforceMode());
    }

    /**
     * Evaluate a policy for the given options. If enforcement mode is "block"
     * and the decision is DENY, this returns the deny decision and callers
     * should throw {@link ai.cyberarmor.policy.PolicyViolationException}.
     *
     * @param opts evaluation options including action, provider, model, prompt text
     * @return the policy {@link Decision}
     */
    public Decision evaluatePolicy(PolicyEnforcer.Options opts) {
        return policyEnforcer.evaluate(opts);
    }

    /**
     * Emit an audit event asynchronously. Events are batched and sent to the
     * control plane in the background.
     *
     * @param eventType the event type (e.g. "llm.invoke", "tool.call")
     * @param data      key/value payload for the event
     * @return the generated event ID (UUID)
     */
    public String emitEvent(String eventType, Map<String, Object> data) {
        return auditEmitter.emit(eventType, data);
    }

    /**
     * Hash a prompt using SHA-256 for safe audit logging without storing raw
     * prompt content.
     *
     * @param text the text to hash
     * @return hex-encoded SHA-256 hash, or fallback hashCode string on error
     */
    public String hashPrompt(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            log.warn("SHA-256 not available, falling back to hashCode: {}", e.getMessage());
            return String.valueOf(text.hashCode());
        }
    }

    /** @return the configuration used by this client */
    public CyberArmorConfig getConfig() {
        return config;
    }

    /** @return the {@link PolicyEnforcer} used by this client */
    public PolicyEnforcer getPolicyEnforcer() {
        return policyEnforcer;
    }

    /** @return the {@link AuditEmitter} used by this client */
    public AuditEmitter getAuditEmitter() {
        return auditEmitter;
    }

    /**
     * Flush pending audit events and release resources.
     * Should be called when the application shuts down.
     */
    @Override
    public void close() {
        log.info("CyberArmorClient closing, flushing audit events...");
        auditEmitter.flush();
        auditEmitter.close();
        policyEnforcer.close();
        log.info("CyberArmorClient closed.");
    }

    /** @return a new {@link Builder} */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Fluent builder for {@link CyberArmorClient}.
     */
    public static class Builder {

        private final CyberArmorConfig config = new CyberArmorConfig();

        /**
         * Set the control plane base URL.
         * Defaults to {@code CYBERARMOR_URL} env var or {@code https://cp.cyberarmor.ai}.
         */
        public Builder controlPlaneUrl(String url) {
            config.setControlPlaneUrl(url);
            return this;
        }

        /**
         * Set the agent ID. Defaults to {@code CYBERARMOR_AGENT_ID} env var.
         */
        public Builder agentId(String agentId) {
            config.setAgentId(agentId);
            return this;
        }

        /**
         * Set the agent secret. Defaults to {@code CYBERARMOR_AGENT_SECRET} env var.
         */
        public Builder agentSecret(String secret) {
            config.setAgentSecret(secret);
            return this;
        }

        /**
         * Set the enforcement mode: "block" (default) or "monitor".
         * Defaults to {@code CYBERARMOR_ENFORCE_MODE} env var.
         */
        public Builder enforceMode(String mode) {
            config.setEnforceMode(mode);
            return this;
        }

        /**
         * Set the HTTP timeout in milliseconds. Defaults to 5000.
         */
        public Builder timeoutMs(int timeoutMs) {
            config.setTimeoutMs(timeoutMs);
            return this;
        }

        /**
         * Set the audit batch size. Defaults to 50.
         */
        public Builder auditBatchSize(int batchSize) {
            config.setAuditBatchSize(batchSize);
            return this;
        }

        /**
         * If true, allow requests when the control plane is unreachable.
         * Defaults to true.
         */
        public Builder failOpen(boolean failOpen) {
            config.setFailOpen(failOpen);
            return this;
        }

        /**
         * Build the {@link CyberArmorClient}, applying environment variable
         * fallbacks for any unset configuration values.
         */
        public CyberArmorClient build() {
            Map<String, String> env = System.getenv();

            if (config.getControlPlaneUrl() == null) {
                config.setControlPlaneUrl(env.getOrDefault("CYBERARMOR_URL", "https://cp.cyberarmor.ai"));
            }
            if (config.getAgentId() == null) {
                config.setAgentId(env.getOrDefault("CYBERARMOR_AGENT_ID", ""));
            }
            if (config.getAgentSecret() == null) {
                config.setAgentSecret(env.getOrDefault("CYBERARMOR_AGENT_SECRET", ""));
            }
            if (config.getEnforceMode() == null) {
                config.setEnforceMode(env.getOrDefault("CYBERARMOR_ENFORCE_MODE", "block"));
            }

            return new CyberArmorClient(this);
        }
    }
}
