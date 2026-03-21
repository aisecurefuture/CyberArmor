"""
AI-Aware Policy Engine Extension for CyberArmor.

Extends the base policy engine with AI-specific risk scoring, prompt injection
detection, DLP scanning, and context-aware decision making.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class DecisionType(str, Enum):
    """Possible outcomes of an AI policy evaluation."""
    # Canonical decision contract
    ALLOW = "ALLOW"
    DENY = "DENY"
    ALLOW_WITH_REDACTION = "ALLOW_WITH_REDACTION"
    ALLOW_WITH_LIMITS = "ALLOW_WITH_LIMITS"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    ALLOW_WITH_AUDIT_ONLY = "ALLOW_WITH_AUDIT_ONLY"
    QUARANTINE = "QUARANTINE"
    # Backward-compatible aliases used in earlier service code
    REDACT = "ALLOW_WITH_REDACTION"
    AUDIT = "ALLOW_WITH_AUDIT_ONLY"
    REQUIRE_MFA = "REQUIRE_APPROVAL"
    RATE_LIMIT = "ALLOW_WITH_LIMITS"


class RiskLevel(str, Enum):
    """Aggregate risk bands returned by the risk scorer."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AIRequestContext:
    """
    Full context of an inbound AI request.

    All fields are optional so callers can supply only what they know.
    The engine degrades gracefully when fields are absent.
    """
    # Identity
    agent_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    tenant_id: Optional[str] = None

    # Request payload
    prompt: Optional[str] = None
    system_prompt: Optional[str] = None
    model: Optional[str] = None
    provider: Optional[str] = None       # "openai", "anthropic", "google", …

    # Response payload (post-call evaluation)
    response_text: Optional[str] = None

    # Routing / environment
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    environment: str = "production"       # production | staging | development
    framework: Optional[str] = None      # "langchain", "llamaindex", …

    # Delegation chain (list of agent_id strings, outermost first)
    delegation_chain: List[str] = field(default_factory=list)

    # Extra arbitrary metadata (tool calls, file names, …)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Timestamps
    request_timestamp: float = field(default_factory=time.time)


@dataclass
class AIDecision:
    """
    The result of evaluating an AIRequestContext against all active policies.
    """
    decision: DecisionType
    risk_level: RiskLevel
    risk_score: float                      # 0.0 – 1.0
    reasons: List[str] = field(default_factory=list)

    # Populated when decision == REDACT
    redacted_prompt: Optional[str] = None
    redacted_response: Optional[str] = None

    # Matched policy identifiers
    matched_policies: List[str] = field(default_factory=list)

    # DLP findings
    dlp_findings: List[Dict[str, Any]] = field(default_factory=list)

    # Injection indicators
    injection_indicators: List[str] = field(default_factory=list)

    # Microseconds taken to evaluate
    evaluation_latency_ms: float = 0.0

    # Forwarded to audit pipeline
    audit_required: bool = True

    def is_allowed(self) -> bool:
        return self.decision in (DecisionType.ALLOW, DecisionType.AUDIT, DecisionType.REDACT)


# ---------------------------------------------------------------------------
# DLP patterns
# ---------------------------------------------------------------------------

_DLP_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    # (label, compiled_pattern, redaction_placeholder)
    ("SSN",
     re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
     "[REDACTED-SSN]"),
    ("CREDIT_CARD",
     re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}"
                r"|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}"
                r"|(?:2131|1800|35\d{3})\d{11})\b"),
     "[REDACTED-CARD]"),
    ("EMAIL",
     re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
     "[REDACTED-EMAIL]"),
    ("PHONE_US",
     re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
     "[REDACTED-PHONE]"),
    ("API_KEY_GENERIC",
     re.compile(r"\b(?:api[_\-]?key|apikey|secret[_\-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
                re.IGNORECASE),
     "[REDACTED-APIKEY]"),
    ("AWS_ACCESS_KEY",
     re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
     "[REDACTED-AWS-KEY]"),
    ("AWS_SECRET_KEY",
     re.compile(r"(?:aws[_\-]?secret|secret[_\-]?access[_\-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?",
                re.IGNORECASE),
     "[REDACTED-AWS-SECRET]"),
    ("PRIVATE_KEY_BLOCK",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
                re.DOTALL),
     "[REDACTED-PRIVATE-KEY]"),
    ("BEARER_TOKEN",
     re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b", re.IGNORECASE),
     "[REDACTED-BEARER]"),
    ("IPV4_PRIVATE",
     re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
                r"|192\.168\.\d{1,3}\.\d{1,3})\b"),
     "[REDACTED-PRIVATE-IP]"),
    ("PASSPORT",
     re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
     "[REDACTED-PASSPORT]"),
    ("DATE_OF_BIRTH",
     re.compile(r"\b(?:dob|date[_\s]of[_\s]birth|born)\s*[:=]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
                re.IGNORECASE),
     "[REDACTED-DOB]"),
]


# ---------------------------------------------------------------------------
# Prompt injection patterns
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("ignore_previous",
     re.compile(r"\b(?:ignore|disregard|forget|override)\s+(?:previous|prior|above|all)\s+(?:instructions?|prompt|context|rules?)\b",
                re.IGNORECASE)),
    ("role_play_jailbreak",
     re.compile(r"\b(?:pretend|act|roleplay|play)\s+(?:you\s+are|as\s+if|like\s+you|that\s+you)\b.*?(?:no\s+restrictions?|uncensored|without\s+limits?|evil|dan|jailbreak)",
                re.IGNORECASE | re.DOTALL)),
    ("dan_jailbreak",
     re.compile(r"\bDAN\b|\bdo\s+anything\s+now\b|\bjailbreak\b|\bunrestricted\s+mode\b",
                re.IGNORECASE)),
    ("system_prompt_leak",
     re.compile(r"\b(?:reveal|show|print|output|repeat|tell\s+me)\s+(?:your\s+)?(?:system\s+prompt|instructions?|initial\s+prompt|base\s+prompt|configuration)\b",
                re.IGNORECASE)),
    ("instruction_injection",
     re.compile(r"(?:^|\n)\s*(?:system|assistant|user)\s*:\s*(?:ignore|you\s+(?:are|must|should|will))",
                re.IGNORECASE | re.MULTILINE)),
    ("token_manipulation",
     re.compile(r"(?:<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|assistant\|>|\[INST\]|\[/INST\]|<s>|</s>)",
                re.IGNORECASE)),
    ("indirect_injection_url",
     re.compile(r"(?:http[s]?://[^\s]+)\s*(?:contains?|has|with)\s*(?:instructions?|prompt|override)",
                re.IGNORECASE)),
    ("exfiltration_attempt",
     re.compile(r"\b(?:send|post|upload|transmit|email)\s+(?:to|me|your|all)\s+(?:http|www|https|ftp|[a-z0-9]+\.[a-z]{2,})",
                re.IGNORECASE)),
    ("prompt_override",
     re.compile(r"\b(?:new\s+prompt|updated?\s+(?:instructions?|prompt)|override\s+(?:mode|settings?|policy)|admin\s+(?:mode|override|access))\b",
                re.IGNORECASE)),
    ("base64_encoded_instruction",
     re.compile(r"(?:base64|b64)(?:\s+encoded?|\s+decode[d]?)?\s*[:=]\s*[A-Za-z0-9+/]{20,}={0,2}",
                re.IGNORECASE)),
]


# ---------------------------------------------------------------------------
# Risk Scorer
# ---------------------------------------------------------------------------

class RiskScorer:
    """
    Stateless risk scoring engine.

    Assigns a float risk score in [0, 1] and accumulates findings
    (DLP hits and injection indicators).
    """

    # Weights for each risk signal (must sum conceptually to ≤ 1)
    _DLP_WEIGHT = 0.25
    _INJECTION_WEIGHT = 0.40
    _DELEGATION_DEPTH_WEIGHT = 0.10
    _MODEL_TIER_WEIGHT = 0.05
    _ENV_WEIGHT = 0.05
    _METADATA_WEIGHT = 0.15

    # High-capability model identifiers that warrant extra scrutiny
    _HIGH_CAPABILITY_MODELS = {
        "gpt-4", "gpt-4o", "gpt-4-turbo", "gpt-4-32k",
        "claude-3-opus", "claude-3-5-sonnet", "claude-opus",
        "gemini-ultra", "gemini-1.5-pro", "gemini-2",
        "llama-3-70b", "mixtral-8x22b",
    }

    def scan_for_dlp(self, text: str) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Scan *text* for sensitive data patterns.

        Returns
        -------
        score : float
            Fractional contribution to overall risk from DLP hits (0–1).
        findings : list
            Each finding is a dict with keys: label, count, positions.
        """
        if not text:
            return 0.0, []

        findings: List[Dict[str, Any]] = []
        total_hits = 0

        for label, pattern, _ in _DLP_PATTERNS:
            matches = list(pattern.finditer(text))
            if matches:
                positions = [(m.start(), m.end()) for m in matches]
                findings.append({"label": label, "count": len(matches), "positions": positions})
                total_hits += len(matches)

        # Diminishing returns: each additional hit adds less marginal risk
        if total_hits == 0:
            return 0.0, findings
        score = min(1.0, 0.3 + 0.07 * total_hits)
        return score, findings

    def redact(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Redact all recognised sensitive patterns from *text*.

        Returns the redacted string and a list of findings.
        """
        if not text:
            return text, []

        redacted = text
        findings: List[Dict[str, Any]] = []

        for label, pattern, placeholder in _DLP_PATTERNS:
            new_text, n_subs = pattern.subn(placeholder, redacted)
            if n_subs:
                findings.append({"label": label, "count": n_subs})
                redacted = new_text

        return redacted, findings

    def scan_for_injection(self, text: str) -> Tuple[float, List[str]]:
        """
        Scan *text* for prompt injection indicators.

        Returns
        -------
        score : float
            Fractional risk contribution from injection signals (0–1).
        indicators : list of str
            Names of matched injection patterns.
        """
        if not text:
            return 0.0, []

        indicators: List[str] = []
        for label, pattern in _INJECTION_PATTERNS:
            if pattern.search(text):
                indicators.append(label)

        if not indicators:
            return 0.0, indicators

        # Each unique indicator type stacks risk, capped at 1.0
        score = min(1.0, 0.25 * len(indicators))
        return score, indicators

    def score(self, ctx: AIRequestContext) -> Tuple[float, List[Dict[str, Any]], List[str]]:
        """
        Compute composite risk score for *ctx*.

        Returns
        -------
        risk_score : float  [0, 1]
        dlp_findings : list
        injection_indicators : list of str
        """
        risk = 0.0
        all_dlp: List[Dict[str, Any]] = []
        all_indicators: List[str] = []

        # --- DLP scan on prompt + response ---
        combined_text = " ".join(filter(None, [ctx.prompt, ctx.system_prompt, ctx.response_text]))
        dlp_score, dlp_findings = self.scan_for_dlp(combined_text)
        risk += dlp_score * self._DLP_WEIGHT
        all_dlp.extend(dlp_findings)

        # --- Injection scan on prompt only (not response, different semantics) ---
        injection_text = " ".join(filter(None, [ctx.prompt, ctx.system_prompt]))
        inj_score, indicators = self.scan_for_injection(injection_text)
        risk += inj_score * self._INJECTION_WEIGHT
        all_indicators.extend(indicators)

        # --- Delegation depth risk ---
        depth = len(ctx.delegation_chain)
        if depth > 0:
            # Each hop adds risk; 5+ hops is inherently suspicious
            depth_risk = min(1.0, depth / 5.0)
            risk += depth_risk * self._DELEGATION_DEPTH_WEIGHT

        # --- Model tier risk ---
        if ctx.model:
            model_lower = ctx.model.lower()
            if any(m in model_lower for m in self._HIGH_CAPABILITY_MODELS):
                risk += 0.5 * self._MODEL_TIER_WEIGHT
            # Code-generation models get extra weight
            if any(kw in model_lower for kw in ("code", "instruct", "codex")):
                risk += 0.5 * self._MODEL_TIER_WEIGHT

        # --- Environment risk ---
        if ctx.environment == "production":
            risk += 1.0 * self._ENV_WEIGHT
        elif ctx.environment == "staging":
            risk += 0.5 * self._ENV_WEIGHT

        # --- Metadata signals ---
        meta = ctx.metadata
        if meta.get("tool_calls"):
            # Agents executing tool calls are higher risk
            risk += 0.5 * self._METADATA_WEIGHT
        if meta.get("file_access"):
            risk += 0.3 * self._METADATA_WEIGHT
        if meta.get("network_access"):
            risk += 0.2 * self._METADATA_WEIGHT

        return min(1.0, risk), all_dlp, all_indicators

    @staticmethod
    def risk_level(score: float) -> RiskLevel:
        if score < 0.25:
            return RiskLevel.LOW
        if score < 0.50:
            return RiskLevel.MEDIUM
        if score < 0.75:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# Policy rule helpers
# ---------------------------------------------------------------------------

@dataclass
class PolicyRule:
    """Minimal representation of a loaded policy rule."""
    rule_id: str
    name: str
    description: str
    # Conditions (all must be True for rule to match)
    min_risk_score: float = 0.0
    blocked_providers: List[str] = field(default_factory=list)
    blocked_models: List[str] = field(default_factory=list)
    require_no_injection: bool = False
    require_no_dlp: bool = False
    max_delegation_depth: Optional[int] = None
    blocked_environments: List[str] = field(default_factory=list)
    # Action
    action: DecisionType = DecisionType.AUDIT
    enabled: bool = True

    def matches(self, ctx: AIRequestContext, score: float,
                dlp_findings: List[Dict], indicators: List[str]) -> bool:
        if not self.enabled:
            return False
        if score < self.min_risk_score:
            return False
        if self.blocked_providers and ctx.provider and ctx.provider.lower() in [
                p.lower() for p in self.blocked_providers]:
            return True
        if self.blocked_models and ctx.model and any(
                m.lower() in ctx.model.lower() for m in self.blocked_models):
            return True
        if self.require_no_injection and indicators:
            return True
        if self.require_no_dlp and dlp_findings:
            return True
        if self.max_delegation_depth is not None and len(ctx.delegation_chain) > self.max_delegation_depth:
            return True
        if self.blocked_environments and ctx.environment in self.blocked_environments:
            return True
        return False


# ---------------------------------------------------------------------------
# AI-Aware Policy Engine
# ---------------------------------------------------------------------------

class AIAwarePolicyEngine:
    """
    AI-Aware Policy Engine.

    Evaluates an AIRequestContext against a set of PolicyRules and produces
    an AIDecision with a deterministic, auditable outcome.

    Usage
    -----
    engine = AIAwarePolicyEngine(rules=[...])
    decision = engine.evaluate(ctx)
    if not decision.is_allowed():
        raise PermissionError(decision.reasons)
    """

    # Default built-in rules (always present, lowest priority)
    _BUILTIN_RULES: List[PolicyRule] = [
        PolicyRule(
            rule_id="builtin-injection-deny",
            name="Deny Prompt Injection",
            description="Block requests containing confirmed prompt injection patterns.",
            require_no_injection=True,
            action=DecisionType.DENY,
            min_risk_score=0.0,
        ),
        PolicyRule(
            rule_id="builtin-dlp-redact",
            name="Redact PII/Secrets",
            description="Redact sensitive data before forwarding to AI provider.",
            require_no_dlp=True,
            action=DecisionType.REDACT,
            min_risk_score=0.0,
        ),
        PolicyRule(
            rule_id="builtin-critical-risk-deny",
            name="Deny Critical Risk",
            description="Deny requests with a critical overall risk score.",
            min_risk_score=0.75,
            action=DecisionType.DENY,
        ),
        PolicyRule(
            rule_id="builtin-high-risk-audit",
            name="Audit High Risk",
            description="Force audit logging for high-risk requests.",
            min_risk_score=0.50,
            action=DecisionType.AUDIT,
        ),
        PolicyRule(
            rule_id="builtin-deep-delegation-quarantine",
            name="Quarantine Deep Delegation",
            description="Quarantine requests with delegation chains deeper than 8 hops.",
            max_delegation_depth=8,
            action=DecisionType.QUARANTINE,
        ),
    ]

    def __init__(
        self,
        rules: Optional[List[PolicyRule]] = None,
        include_builtins: bool = True,
        scorer: Optional[RiskScorer] = None,
    ) -> None:
        self._scorer = scorer or RiskScorer()
        self._rules: List[PolicyRule] = []
        if include_builtins:
            self._rules.extend(self._BUILTIN_RULES)
        if rules:
            self._rules.extend(rules)

    def add_rule(self, rule: PolicyRule) -> None:
        """Append a rule to the active rule set."""
        self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by its ID. Returns True if found and removed."""
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.rule_id != rule_id]
        return len(self._rules) < before

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def evaluate(self, ctx: AIRequestContext) -> AIDecision:
        """
        Evaluate *ctx* against all active policies.

        The algorithm:
          1. Run the risk scorer to get a composite score and raw findings.
          2. Walk all rules in order; collect matching rules and their actions.
          3. Apply the most-restrictive action (DENY > QUARANTINE > REQUIRE_MFA >
             RATE_LIMIT > REDACT > AUDIT > ALLOW).
          4. If REDACT is the final action, run the redactor on prompt and response.
          5. Return a fully-populated AIDecision.
        """
        t_start = time.perf_counter()

        # Step 1: score
        risk_score, dlp_findings, injection_indicators = self._scorer.score(ctx)
        risk_level = RiskScorer.risk_level(risk_score)

        # Step 2: match rules
        matched_rules: List[PolicyRule] = []
        for rule in self._rules:
            if rule.matches(ctx, risk_score, dlp_findings, injection_indicators):
                matched_rules.append(rule)

        # Step 3: determine most-restrictive action
        action_priority = {
            DecisionType.DENY: 6,
            DecisionType.QUARANTINE: 5,
            DecisionType.REQUIRE_MFA: 4,
            DecisionType.RATE_LIMIT: 3,
            DecisionType.REDACT: 2,
            DecisionType.AUDIT: 1,
            DecisionType.ALLOW: 0,
        }

        final_action = DecisionType.ALLOW
        reasons: List[str] = []
        matched_policy_ids: List[str] = []

        if not matched_rules:
            # No rule fired — allow with implicit audit at medium+ risk
            if risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
                final_action = DecisionType.AUDIT
                reasons.append(f"Implicit audit: risk_score={risk_score:.2f} ({risk_level})")
            else:
                final_action = DecisionType.ALLOW
                reasons.append("No matching policies; request allowed.")
        else:
            for rule in matched_rules:
                matched_policy_ids.append(rule.rule_id)
                reasons.append(f"[{rule.rule_id}] {rule.description}")
                if action_priority[rule.action] > action_priority[final_action]:
                    final_action = rule.action

        # Augment reasons with risk detail
        if injection_indicators:
            reasons.append(f"Injection indicators detected: {', '.join(injection_indicators)}")
        if dlp_findings:
            labels = [f["label"] for f in dlp_findings]
            reasons.append(f"DLP findings: {', '.join(labels)}")

        # Step 4: redact if needed
        redacted_prompt: Optional[str] = None
        redacted_response: Optional[str] = None

        if final_action == DecisionType.REDACT:
            if ctx.prompt:
                redacted_prompt, _ = self._scorer.redact(ctx.prompt)
            if ctx.response_text:
                redacted_response, _ = self._scorer.redact(ctx.response_text)

        # Step 5: build decision
        latency_ms = (time.perf_counter() - t_start) * 1000.0

        decision = AIDecision(
            decision=final_action,
            risk_level=risk_level,
            risk_score=round(risk_score, 4),
            reasons=reasons,
            redacted_prompt=redacted_prompt,
            redacted_response=redacted_response,
            matched_policies=matched_policy_ids,
            dlp_findings=dlp_findings,
            injection_indicators=injection_indicators,
            evaluation_latency_ms=round(latency_ms, 3),
            audit_required=final_action in (
                DecisionType.ALLOW,
                DecisionType.AUDIT,
                DecisionType.REDACT,
                DecisionType.RATE_LIMIT,
                DecisionType.REQUIRE_MFA,
            ),
        )

        logger.debug(
            "ai_policy_evaluate agent=%s decision=%s score=%.3f latency=%.2fms",
            ctx.agent_id, final_action, risk_score, latency_ms,
        )

        return decision

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def is_allowed(self, ctx: AIRequestContext) -> bool:
        """Quick boolean check — does not surface redaction or audit info."""
        return self.evaluate(ctx).is_allowed()

    def evaluate_and_raise(self, ctx: AIRequestContext) -> AIDecision:
        """
        Evaluate and raise RuntimeError if the request is denied or quarantined.
        Returns the AIDecision for allowed/audited/redacted outcomes.
        """
        decision = self.evaluate(ctx)
        if decision.decision in (DecisionType.DENY, DecisionType.QUARANTINE):
            raise PermissionError(
                f"AI request blocked by policy. Decision={decision.decision}, "
                f"reasons={decision.reasons}"
            )
        return decision

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"AIAwarePolicyEngine(rules={len(self._rules)}, "
            f"builtins={len(self._BUILTIN_RULES)})"
        )
