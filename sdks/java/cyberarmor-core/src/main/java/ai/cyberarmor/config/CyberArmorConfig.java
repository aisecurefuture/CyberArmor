package ai.cyberarmor.config;

/**
 * CyberArmorConfig holds all configuration parameters for the CyberArmor SDK.
 *
 * <p>Values can be set via the Builder on {@link ai.cyberarmor.CyberArmorClient}
 * or loaded from environment variables as fallbacks.
 */
public class CyberArmorConfig {

    /** Base URL of the CyberArmor Control Plane API */
    private String controlPlaneUrl;

    /** Unique agent identifier issued by the Control Plane */
    private String agentId;

    /** Agent secret for HMAC-signed request authentication */
    private String agentSecret;

    /**
     * Enforcement mode. Valid values:
     * <ul>
     *   <li>{@code block} — deny requests that violate policy (default)</li>
     *   <li>{@code monitor} — allow all requests but emit audit events</li>
     * </ul>
     */
    private String enforceMode;

    /** HTTP request timeout in milliseconds (default: 5000) */
    private int timeoutMs = 5000;

    /** Number of audit events to buffer before flushing to the control plane (default: 50) */
    private int auditBatchSize = 50;

    /**
     * If {@code true} (default), allow requests when the control plane is
     * unreachable (fail-open). If {@code false}, deny requests on connectivity
     * errors (fail-closed / fail-secure).
     */
    private boolean failOpen = true;

    /** Maximum number of retry attempts for transient HTTP errors */
    private int maxRetries = 3;

    /** Interval in seconds between background audit flush cycles (default: 30) */
    private int auditFlushIntervalSeconds = 30;

    /** Optional tenant ID for multi-tenant deployments */
    private String tenantId;

    /** Optional environment label (e.g., "production", "staging") */
    private String environment;

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    public CyberArmorConfig() {
    }

    public CyberArmorConfig(String controlPlaneUrl, String agentId, String agentSecret) {
        this.controlPlaneUrl = controlPlaneUrl;
        this.agentId = agentId;
        this.agentSecret = agentSecret;
    }

    // -------------------------------------------------------------------------
    // Getters and Setters
    // -------------------------------------------------------------------------

    public String getControlPlaneUrl() {
        return controlPlaneUrl;
    }

    public void setControlPlaneUrl(String controlPlaneUrl) {
        this.controlPlaneUrl = controlPlaneUrl;
    }

    public String getAgentId() {
        return agentId;
    }

    public void setAgentId(String agentId) {
        this.agentId = agentId;
    }

    public String getAgentSecret() {
        return agentSecret;
    }

    public void setAgentSecret(String agentSecret) {
        this.agentSecret = agentSecret;
    }

    public String getEnforceMode() {
        return enforceMode;
    }

    public void setEnforceMode(String enforceMode) {
        this.enforceMode = enforceMode;
    }

    public int getTimeoutMs() {
        return timeoutMs;
    }

    public void setTimeoutMs(int timeoutMs) {
        if (timeoutMs <= 0) {
            throw new IllegalArgumentException("timeoutMs must be positive, got: " + timeoutMs);
        }
        this.timeoutMs = timeoutMs;
    }

    public int getAuditBatchSize() {
        return auditBatchSize;
    }

    public void setAuditBatchSize(int auditBatchSize) {
        if (auditBatchSize <= 0) {
            throw new IllegalArgumentException("auditBatchSize must be positive, got: " + auditBatchSize);
        }
        this.auditBatchSize = auditBatchSize;
    }

    public boolean isFailOpen() {
        return failOpen;
    }

    public void setFailOpen(boolean failOpen) {
        this.failOpen = failOpen;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(int maxRetries) {
        this.maxRetries = maxRetries;
    }

    public int getAuditFlushIntervalSeconds() {
        return auditFlushIntervalSeconds;
    }

    public void setAuditFlushIntervalSeconds(int auditFlushIntervalSeconds) {
        this.auditFlushIntervalSeconds = auditFlushIntervalSeconds;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getEnvironment() {
        return environment;
    }

    public void setEnvironment(String environment) {
        this.environment = environment;
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    /** @return true if enforcement mode is "block" */
    public boolean isBlockMode() {
        return "block".equalsIgnoreCase(enforceMode);
    }

    /** @return true if enforcement mode is "monitor" */
    public boolean isMonitorMode() {
        return "monitor".equalsIgnoreCase(enforceMode);
    }

    @Override
    public String toString() {
        return "CyberArmorConfig{" +
                "controlPlaneUrl='" + controlPlaneUrl + '\'' +
                ", agentId='" + agentId + '\'' +
                ", enforceMode='" + enforceMode + '\'' +
                ", timeoutMs=" + timeoutMs +
                ", auditBatchSize=" + auditBatchSize +
                ", failOpen=" + failOpen +
                ", maxRetries=" + maxRetries +
                ", tenantId='" + tenantId + '\'' +
                ", environment='" + environment + '\'' +
                '}';
    }
}
