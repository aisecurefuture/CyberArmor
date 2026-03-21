// Package policy provides policy decision types and enforcement for CyberArmor.
package policy

import "fmt"

// DecisionType represents the outcome of a policy evaluation.
type DecisionType string

const (
	DecisionTypeAllow              DecisionType = "ALLOW"
	DecisionTypeDeny               DecisionType = "DENY"
	DecisionTypeAllowWithRedaction DecisionType = "ALLOW_WITH_REDACTION"
	DecisionTypeAllowWithLimits    DecisionType = "ALLOW_WITH_LIMITS"
	DecisionTypeRequireApproval    DecisionType = "REQUIRE_APPROVAL"
	DecisionTypeAllowWithAuditOnly DecisionType = "ALLOW_WITH_AUDIT_ONLY"
	DecisionTypeQuarantine         DecisionType = "QUARANTINE"
)

// Decision is the result of a policy evaluation.
type Decision struct {
	Type                 DecisionType `json:"decision"`
	ReasonCode           string       `json:"reason_code"`
	RiskScore            float64      `json:"risk_score"`
	PolicyID             string       `json:"policy_id,omitempty"`
	RedactionTargets     []string     `json:"redaction_targets,omitempty"`
	ApprovalRequiredFrom string       `json:"approval_required_from,omitempty"`
	Explanation          string       `json:"explanation,omitempty"`
	LatencyMs            int          `json:"latency_ms,omitempty"`
}

// IsAllowed returns true if the decision permits the action.
func (d Decision) IsAllowed() bool {
	switch d.Type {
	case DecisionTypeAllow, DecisionTypeAllowWithRedaction,
		DecisionTypeAllowWithLimits, DecisionTypeAllowWithAuditOnly:
		return true
	}
	return false
}

// RequiresRedaction returns true if response data must be redacted.
func (d Decision) RequiresRedaction() bool {
	return d.Type == DecisionTypeAllowWithRedaction
}

// PolicyViolationError is returned when a policy blocks an action.
type PolicyViolationError struct {
	Decision Decision
}

func (e *PolicyViolationError) Error() string {
	return fmt.Sprintf("CyberArmor policy violation: %s (%s)", e.Decision.ReasonCode, e.Decision.Type)
}
