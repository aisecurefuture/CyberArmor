"""
Policy decision types and errors for the CyberArmor SDK.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DecisionType(str, Enum):
    """
    All possible outcomes from a policy evaluation.

    Values mirror the server-side DecisionType in ai_policy_engine.py.
    """
    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    AUDIT = "audit"
    REQUIRE_MFA = "require_mfa"
    RATE_LIMIT = "rate_limit"
    QUARANTINE = "quarantine"


@dataclass
class Decision:
    """
    The result of evaluating a request against CyberArmor policies.

    Returned by PolicyEnforcer.evaluate() and CyberArmorClient.evaluate_policy().

    Fields
    ------
    decision : DecisionType
        The policy outcome.
    risk_score : float
        Composite risk score in [0, 1].
    reasons : list of str
        Human-readable explanations for the decision.
    redacted_prompt : str or None
        DLP-redacted version of the prompt (set when decision == REDACT).
    redacted_response : str or None
        DLP-redacted version of the response (set when decision == REDACT).
    matched_policies : list of str
        Identifiers of policies that fired.
    dlp_findings : list of dict
        Raw DLP findings (label, count, positions).
    injection_indicators : list of str
        Names of injection patterns detected.
    evaluation_latency_ms : float
        How long the evaluation took (milliseconds).
    request_id : str or None
        Server-assigned request ID for correlation.
    metadata : dict
        Any additional fields from the API response.
    """

    decision: DecisionType = DecisionType.ALLOW
    risk_score: float = 0.0
    reasons: List[str] = field(default_factory=list)
    redacted_prompt: Optional[str] = None
    redacted_response: Optional[str] = None
    matched_policies: List[str] = field(default_factory=list)
    dlp_findings: List[Dict[str, Any]] = field(default_factory=list)
    injection_indicators: List[str] = field(default_factory=list)
    evaluation_latency_ms: float = 0.0
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Convenience predicates
    # ------------------------------------------------------------------

    def is_allowed(self) -> bool:
        """True when the request may proceed (with possible side-effects)."""
        return self.decision in (
            DecisionType.ALLOW,
            DecisionType.AUDIT,
            DecisionType.REDACT,
        )

    def is_denied(self) -> bool:
        """True when the request must be blocked."""
        return self.decision in (DecisionType.DENY, DecisionType.QUARANTINE)

    def requires_redaction(self) -> bool:
        return self.decision == DecisionType.REDACT

    def requires_mfa(self) -> bool:
        return self.decision == DecisionType.REQUIRE_MFA

    def is_rate_limited(self) -> bool:
        return self.decision == DecisionType.RATE_LIMIT

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "redacted_prompt": self.redacted_prompt,
            "redacted_response": self.redacted_response,
            "matched_policies": self.matched_policies,
            "dlp_findings": self.dlp_findings,
            "injection_indicators": self.injection_indicators,
            "evaluation_latency_ms": self.evaluation_latency_ms,
            "request_id": self.request_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "Decision":
        """
        Build a Decision from a raw API response dict.

        Handles both the full schema and the minimal schema returned
        by the local policy engine.
        """
        raw_decision = data.get("decision", "allow")
        try:
            decision_type = DecisionType(raw_decision)
        except ValueError:
            decision_type = DecisionType.AUDIT  # safe default

        return cls(
            decision=decision_type,
            risk_score=float(data.get("risk_score", 0.0)),
            reasons=list(data.get("reasons", [])),
            redacted_prompt=data.get("redacted_prompt"),
            redacted_response=data.get("redacted_response"),
            matched_policies=list(data.get("matched_policies", [])),
            dlp_findings=list(data.get("dlp_findings", [])),
            injection_indicators=list(data.get("injection_indicators", [])),
            evaluation_latency_ms=float(data.get("evaluation_latency_ms", 0.0)),
            request_id=data.get("request_id"),
            metadata={
                k: v for k, v in data.items()
                if k not in (
                    "decision", "risk_score", "reasons", "redacted_prompt",
                    "redacted_response", "matched_policies", "dlp_findings",
                    "injection_indicators", "evaluation_latency_ms", "request_id",
                )
            },
        )

    def __repr__(self) -> str:
        return (
            f"Decision(decision={self.decision!r}, "
            f"risk_score={self.risk_score:.3f}, "
            f"reasons={self.reasons!r})"
        )


class PolicyViolationError(Exception):
    """
    Raised when a policy evaluation returns DENY or QUARANTINE and
    raise_on_deny=True is set.
    """

    def __init__(self, decision: Decision, message: Optional[str] = None) -> None:
        self.decision = decision
        default_msg = (
            f"Request blocked by CyberArmor policy: "
            f"decision={decision.decision.value}, "
            f"risk_score={decision.risk_score:.3f}, "
            f"reasons={decision.reasons}"
        )
        super().__init__(message or default_msg)

    def __repr__(self) -> str:
        return f"PolicyViolationError(decision={self.decision!r})"
