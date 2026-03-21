package ai.cyberarmor.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Represents the result of a policy evaluation from the CyberArmor control plane.
 *
 * <p>Callers should check {@link #isAllowed()} first, then inspect additional
 * fields such as {@link #getRiskScore()}, {@link #getRedactionTargets()}, and
 * {@link #getExplanation()} as needed.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Decision {

    /**
     * The set of possible policy decision outcomes.
     */
    public enum DecisionType {

        /** Request is permitted as-is */
        ALLOW("ALLOW"),

        /** Request is denied; agent must not proceed */
        DENY("DENY"),

        /** Request is permitted but the response must be redacted */
        ALLOW_WITH_REDACTION("ALLOW_WITH_REDACTION"),

        /** Request is permitted but rate/token limits are applied */
        ALLOW_WITH_LIMITS("ALLOW_WITH_LIMITS"),

        /** Request requires human approval before proceeding */
        REQUIRE_APPROVAL("REQUIRE_APPROVAL"),

        /** Request is permitted but only an audit event is emitted */
        ALLOW_WITH_AUDIT_ONLY("ALLOW_WITH_AUDIT_ONLY"),

        /** Request is quarantined for security review */
        QUARANTINE("QUARANTINE");

        private final String value;

        DecisionType(String value) {
            this.value = value;
        }

        @JsonValue
        public String getValue() {
            return value;
        }

        @JsonCreator
        public static DecisionType fromValue(String value) {
            for (DecisionType dt : values()) {
                if (dt.value.equalsIgnoreCase(value)) {
                    return dt;
                }
            }
            // Default to DENY for unknown values to fail-secure
            return DENY;
        }
    }

    @JsonProperty("decision")
    private DecisionType type;

    @JsonProperty("reason_code")
    private String reasonCode;

    @JsonProperty("risk_score")
    private double riskScore;

    @JsonProperty("policy_id")
    private String policyId;

    @JsonProperty("redaction_targets")
    private List<String> redactionTargets;

    @JsonProperty("explanation")
    private String explanation;

    @JsonProperty("redacted_prompt")
    private String redactedPrompt;

    @JsonProperty("latency_ms")
    private Long latencyMs;

    @JsonProperty("request_id")
    private String requestId;

    @JsonProperty("tenant_id")
    private String tenantId;

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    public Decision() {
    }

    public Decision(DecisionType type, String reasonCode) {
        this.type = type;
        this.reasonCode = reasonCode;
    }

    public Decision(DecisionType type, String reasonCode, double riskScore, String policyId,
                    List<String> redactionTargets, String explanation, Long latencyMs) {
        this.type = type;
        this.reasonCode = reasonCode;
        this.riskScore = riskScore;
        this.policyId = policyId;
        this.redactionTargets = redactionTargets;
        this.explanation = explanation;
        this.latencyMs = latencyMs;
    }

    // -------------------------------------------------------------------------
    // Key helper methods
    // -------------------------------------------------------------------------

    /**
     * Returns {@code true} if the decision type permits the request to proceed.
     * Specifically, ALLOW, ALLOW_WITH_REDACTION, ALLOW_WITH_LIMITS, and
     * ALLOW_WITH_AUDIT_ONLY are all considered "allowed".
     */
    public boolean isAllowed() {
        if (type == null) return false;
        switch (type) {
            case ALLOW:
            case ALLOW_WITH_REDACTION:
            case ALLOW_WITH_LIMITS:
            case ALLOW_WITH_AUDIT_ONLY:
                return true;
            default:
                return false;
        }
    }

    /** @return true if this decision requires redacting part of the response */
    public boolean requiresRedaction() {
        return type == DecisionType.ALLOW_WITH_REDACTION;
    }

    /** @return true if this decision requires human approval */
    public boolean requiresApproval() {
        return type == DecisionType.REQUIRE_APPROVAL;
    }

    /** @return true if the decision is a hard deny */
    public boolean isDenied() {
        return type == DecisionType.DENY;
    }

    /** @return true if the request has been quarantined */
    public boolean isQuarantined() {
        return type == DecisionType.QUARANTINE;
    }

    // -------------------------------------------------------------------------
    // Static factory methods
    // -------------------------------------------------------------------------

    public static Decision allow() {
        return new Decision(DecisionType.ALLOW, "POLICY_ALLOW");
    }

    public static Decision deny(String reasonCode) {
        return new Decision(DecisionType.DENY, reasonCode);
    }

    public static Decision failOpen() {
        return new Decision(DecisionType.ALLOW, "FAIL_OPEN");
    }

    public static Decision allowDefault() {
        return allow();
    }

    // -------------------------------------------------------------------------
    // Getters and Setters
    // -------------------------------------------------------------------------

    public DecisionType getType() { return type; }
    public void setType(DecisionType type) { this.type = type; }

    public String getDecisionType() { return type != null ? type.getValue() : null; }

    public String getReasonCode() { return reasonCode; }
    public void setReasonCode(String reasonCode) { this.reasonCode = reasonCode; }

    public String getReason() { return reasonCode; }

    public double getRiskScore() { return riskScore; }
    public void setRiskScore(double riskScore) { this.riskScore = riskScore; }

    public String getPolicyId() { return policyId; }
    public void setPolicyId(String policyId) { this.policyId = policyId; }

    public List<String> getRedactionTargets() {
        return redactionTargets != null ? redactionTargets : Collections.emptyList();
    }
    public void setRedactionTargets(List<String> redactionTargets) { this.redactionTargets = redactionTargets; }

    public String getExplanation() { return explanation; }
    public void setExplanation(String explanation) { this.explanation = explanation; }

    public String getRedactedPrompt() { return redactedPrompt; }
    public void setRedactedPrompt(String redactedPrompt) { this.redactedPrompt = redactedPrompt; }

    public Long getLatencyMs() { return latencyMs; }
    public void setLatencyMs(Long latencyMs) { this.latencyMs = latencyMs; }

    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }

    public String getTenantId() { return tenantId; }
    public void setTenantId(String tenantId) { this.tenantId = tenantId; }

    // -------------------------------------------------------------------------
    // Object overrides
    // -------------------------------------------------------------------------

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Decision)) return false;
        Decision decision = (Decision) o;
        return Double.compare(decision.riskScore, riskScore) == 0
                && type == decision.type
                && Objects.equals(reasonCode, decision.reasonCode)
                && Objects.equals(policyId, decision.policyId)
                && Objects.equals(requestId, decision.requestId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, reasonCode, riskScore, policyId, requestId);
    }

    @Override
    public String toString() {
        return "Decision{" +
                "type=" + type +
                ", reasonCode='" + reasonCode + '\'' +
                ", riskScore=" + riskScore +
                ", policyId='" + policyId + '\'' +
                ", allowed=" + isAllowed() +
                ", latencyMs=" + latencyMs +
                '}';
    }
}
