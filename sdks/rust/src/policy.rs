// cyberarmor-sdk/src/policy.rs
//
// Policy decision types returned by the CyberArmor policy engine.

use serde::{Deserialize, Serialize};

/// All possible decision types the policy engine may return.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionType {
    /// The request is permitted without restrictions.
    Allow,
    /// The request is denied.
    Deny,
    /// The request is permitted after PII/secrets have been removed from the prompt.
    AllowWithRedaction,
    /// The request is permitted subject to rate or token limits.
    AllowWithLimits,
    /// The request must be routed for human approval before proceeding.
    RequireApproval,
    /// The request is permitted but is recorded for compliance purposes.
    AllowWithAuditOnly,
    /// The request is isolated for investigation.
    Quarantine,
}

impl DecisionType {
    /// Returns `true` if this decision type implies the request should proceed
    /// without raising a policy violation error.
    pub fn is_allowed_variant(&self) -> bool {
        matches!(
            self,
            Self::Allow
                | Self::AllowWithRedaction
                | Self::AllowWithLimits
                | Self::AllowWithAuditOnly
        )
    }
}

impl std::fmt::Display for DecisionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Allow               => "ALLOW",
            Self::Deny                => "DENY",
            Self::AllowWithRedaction  => "ALLOW_WITH_REDACTION",
            Self::AllowWithLimits     => "ALLOW_WITH_LIMITS",
            Self::RequireApproval     => "REQUIRE_APPROVAL",
            Self::AllowWithAuditOnly  => "ALLOW_WITH_AUDIT_ONLY",
            Self::Quarantine          => "QUARANTINE",
        };
        f.write_str(s)
    }
}

/// The result of a policy evaluation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Whether the AI request is permitted to proceed.
    pub allowed: bool,

    /// The specific decision type from the policy engine.
    pub decision_type: DecisionType,

    /// Optional human-readable explanation of the decision.
    pub reason: Option<String>,

    /// When `decision_type` is [`DecisionType::AllowWithRedaction`], this
    /// field contains the prompt after PII and secrets have been removed.
    pub redacted_prompt: Option<String>,
}

impl PolicyDecision {
    /// Returns `true` if the request is allowed to proceed.
    pub fn is_allowed(&self) -> bool {
        self.allowed
    }
}
