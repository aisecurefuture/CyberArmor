package ai.cyberarmor.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Spring Boot configuration properties for CyberArmor, bound from the
 * {@code cyberarmor} prefix in {@code application.yml} / {@code application.properties}.
 *
 * <p>Example YAML:
 * <pre>{@code
 * cyberarmor:
 *   enabled: true
 *   control-plane-url: https://cp.cyberarmor.ai
 *   agent-id: ${CYBERARMOR_AGENT_ID}
 *   agent-secret: ${CYBERARMOR_AGENT_SECRET}
 *   enforce-mode: block
 *   timeout-ms: 5000
 *   audit-batch-size: 50
 *   fail-open: true
 * }</pre>
 */
@ConfigurationProperties(prefix = "cyberarmor")
public class CyberArmorProperties {

    /**
     * Whether the CyberArmor integration is enabled (default: true).
     */
    private boolean enabled = true;

    /**
     * Base URL of the CyberArmor Control Plane API.
     * Defaults to {@code https://cp.cyberarmor.ai}.
     */
    private String controlPlaneUrl = "https://cp.cyberarmor.ai";

    /**
     * Unique agent identifier issued by the Control Plane.
     */
    private String agentId;

    /**
     * Agent secret for HMAC-signed request authentication.
     */
    private String agentSecret;

    /**
     * Enforcement mode: {@code block} (default) or {@code monitor}.
     */
    private String enforceMode = "block";

    /**
     * HTTP request timeout in milliseconds (default: 5000).
     */
    private int timeoutMs = 5000;

    /**
     * Number of audit events to buffer before flushing (default: 50).
     */
    private int auditBatchSize = 50;

    /**
     * If {@code true}, allow requests when control plane is unreachable (default: true).
     */
    private boolean failOpen = true;

    /**
     * Optional tenant ID for multi-tenant deployments.
     */
    private String tenantId;

    /**
     * Optional environment label (e.g., "production", "staging").
     */
    private String environment;

    /**
     * Interval in seconds between background audit flush cycles (default: 30).
     */
    private int auditFlushIntervalSeconds = 30;

    // -------------------------------------------------------------------------
    // Getters and Setters
    // -------------------------------------------------------------------------

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getControlPlaneUrl() { return controlPlaneUrl; }
    public void setControlPlaneUrl(String controlPlaneUrl) { this.controlPlaneUrl = controlPlaneUrl; }

    public String getAgentId() { return agentId; }
    public void setAgentId(String agentId) { this.agentId = agentId; }

    public String getAgentSecret() { return agentSecret; }
    public void setAgentSecret(String agentSecret) { this.agentSecret = agentSecret; }

    public String getEnforceMode() { return enforceMode; }
    public void setEnforceMode(String enforceMode) { this.enforceMode = enforceMode; }

    public int getTimeoutMs() { return timeoutMs; }
    public void setTimeoutMs(int timeoutMs) { this.timeoutMs = timeoutMs; }

    public int getAuditBatchSize() { return auditBatchSize; }
    public void setAuditBatchSize(int auditBatchSize) { this.auditBatchSize = auditBatchSize; }

    public boolean isFailOpen() { return failOpen; }
    public void setFailOpen(boolean failOpen) { this.failOpen = failOpen; }

    public String getTenantId() { return tenantId; }
    public void setTenantId(String tenantId) { this.tenantId = tenantId; }

    public String getEnvironment() { return environment; }
    public void setEnvironment(String environment) { this.environment = environment; }

    public int getAuditFlushIntervalSeconds() { return auditFlushIntervalSeconds; }
    public void setAuditFlushIntervalSeconds(int auditFlushIntervalSeconds) {
        this.auditFlushIntervalSeconds = auditFlushIntervalSeconds;
    }
}
