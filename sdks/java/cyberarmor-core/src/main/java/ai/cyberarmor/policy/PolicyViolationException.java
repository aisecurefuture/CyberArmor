package ai.cyberarmor.policy;

/**
 * Thrown when the CyberArmor policy engine returns a non-allowed {@link Decision}
 * and the client is configured with enforcement mode "block".
 *
 * <p>Usage:
 * <pre>{@code
 * Decision decision = client.evaluatePolicy(opts);
 * if (!decision.isAllowed()) {
 *     throw new PolicyViolationException(decision);
 * }
 * }</pre>
 */
public class PolicyViolationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** The policy decision that triggered this exception */
    private final Decision decision;

    /**
     * Construct a PolicyViolationException from a deny {@link Decision}.
     *
     * @param decision the policy decision (should have isAllowed() == false)
     */
    public PolicyViolationException(Decision decision) {
        super(buildMessage(decision));
        this.decision = decision;
    }

    /**
     * Construct with a custom message and a deny {@link Decision}.
     *
     * @param message  a human-readable description of the violation
     * @param decision the policy decision
     */
    public PolicyViolationException(String message, Decision decision) {
        super(message);
        this.decision = decision;
    }

    /**
     * Construct with a cause.
     *
     * @param decision the policy decision
     * @param cause    the underlying cause
     */
    public PolicyViolationException(Decision decision, Throwable cause) {
        super(buildMessage(decision), cause);
        this.decision = decision;
    }

    /**
     * Returns the {@link Decision} that caused this exception to be thrown.
     * Callers can inspect {@link Decision#getType()}, {@link Decision#getReasonCode()},
     * {@link Decision#getRiskScore()}, and {@link Decision#getExplanation()} for
     * more context.
     *
     * @return the policy decision
     */
    public Decision getDecision() {
        return decision;
    }

    /**
     * Convenience method to get the decision type directly.
     *
     * @return the {@link Decision.DecisionType}
     */
    public Decision.DecisionType getDecisionType() {
        return decision != null ? decision.getType() : null;
    }

    /**
     * Convenience method to get the reason code directly.
     *
     * @return the reason code string (e.g. "PII_DETECTED", "CONTENT_POLICY_VIOLATION")
     */
    public String getReasonCode() {
        return decision != null ? decision.getReasonCode() : null;
    }

    /**
     * Convenience method to get the risk score directly.
     *
     * @return the risk score (0.0 to 1.0)
     */
    public double getRiskScore() {
        return decision != null ? decision.getRiskScore() : 0.0;
    }

    /**
     * Convenience method to get the policy ID that was violated.
     *
     * @return the policy ID or null if not available
     */
    public String getPolicyId() {
        return decision != null ? decision.getPolicyId() : null;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static String buildMessage(Decision decision) {
        if (decision == null) {
            return "Policy violation: decision is null";
        }
        StringBuilder sb = new StringBuilder("Policy violation");
        if (decision.getType() != null) {
            sb.append(": decision=").append(decision.getType().getValue());
        }
        if (decision.getReasonCode() != null && !decision.getReasonCode().isEmpty()) {
            sb.append(", reason=").append(decision.getReasonCode());
        }
        if (decision.getPolicyId() != null) {
            sb.append(", policy=").append(decision.getPolicyId());
        }
        sb.append(", riskScore=").append(String.format("%.3f", decision.getRiskScore()));
        if (decision.getExplanation() != null && !decision.getExplanation().isEmpty()) {
            sb.append(", explanation=").append(decision.getExplanation());
        }
        return sb.toString();
    }
}
