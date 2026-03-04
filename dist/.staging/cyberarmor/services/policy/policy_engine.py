"""Extensible Policy Evaluation Engine.

Supports AND/OR condition groups with nested rules, multiple action modes
(monitor, block, warn, allow), and compliance framework tagging.

Condition Schema:
{
    "operator": "AND" | "OR",
    "rules": [
        {"field": "request.url", "operator": "matches", "value": "*.openai.com/*"},
        {
            "operator": "OR",
            "rules": [
                {"field": "content.has_pii", "operator": "equals", "value": true},
                {"field": "content.classification", "operator": "in", "value": ["confidential"]}
            ]
        }
    ]
}
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PolicyEvalResult:
    """Result of evaluating a single policy against a context."""
    matched: bool
    policy_id: str
    policy_name: str
    action: str  # monitor, block, warn, allow
    reason: str = ""
    matched_rules: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)


@dataclass
class EvaluationContext:
    """Context object passed through policy evaluation.

    Fields are accessed via dot notation in policy conditions:
        "request.url" -> context.request.url
        "content.has_pii" -> context.content.has_pii
        "user.department" -> context.user.department
    """
    request: Dict[str, Any] = field(default_factory=dict)
    content: Dict[str, Any] = field(default_factory=dict)
    user: Dict[str, Any] = field(default_factory=dict)
    endpoint: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_flat_dict(self) -> Dict[str, Any]:
        """Flatten to a single dict for rule evaluation."""
        result = {}
        for prefix, section in [
            ("request", self.request),
            ("content", self.content),
            ("user", self.user),
            ("endpoint", self.endpoint),
            ("metadata", self.metadata),
        ]:
            if isinstance(section, dict):
                for k, v in section.items():
                    result[f"{prefix}.{k}"] = v
        return result


class PolicyEngine:
    """Evaluates a set of policies against a given context.

    Usage:
        engine = PolicyEngine()
        context = EvaluationContext(
            request={"url": "https://chat.openai.com/api", "method": "POST"},
            content={"has_pii": True, "classification": "confidential"},
            user={"department": "engineering", "role": "developer"},
        )
        results = engine.evaluate(policies, context)
        # results is a list of PolicyEvalResult, sorted by priority
    """

    def evaluate(
        self,
        policies: List[dict],
        context: EvaluationContext,
    ) -> List[PolicyEvalResult]:
        """Evaluate all enabled policies against the context.

        Returns list of matched policies sorted by priority (lower = higher priority).
        """
        flat = context.to_flat_dict()
        results = []

        # Sort by priority (lower number = higher priority)
        sorted_policies = sorted(policies, key=lambda p: p.get("priority", 100))

        for policy in sorted_policies:
            if not policy.get("enabled", True):
                continue

            conditions = policy.get("conditions")
            matched = False
            matched_rules = []

            if conditions:
                matched, matched_rules = self._evaluate_condition_group(
                    conditions, flat
                )
            else:
                # No conditions = always matches (legacy support)
                rules = policy.get("rules", {})
                if rules:
                    matched = self._evaluate_legacy_rules(rules, flat)
                else:
                    matched = True

            if matched:
                results.append(
                    PolicyEvalResult(
                        matched=True,
                        policy_id=policy.get("id", ""),
                        policy_name=policy.get("name", ""),
                        action=policy.get("action", "monitor"),
                        reason=f"Matched {len(matched_rules)} rule(s)",
                        matched_rules=matched_rules,
                        compliance_frameworks=policy.get("compliance_frameworks", []),
                    )
                )

        return results

    def evaluate_first_match(
        self,
        policies: List[dict],
        context: EvaluationContext,
    ) -> Optional[PolicyEvalResult]:
        """Evaluate and return only the first (highest priority) match."""
        results = self.evaluate(policies, context)
        return results[0] if results else None

    def _evaluate_condition_group(
        self, conditions: dict, flat_context: dict
    ) -> tuple[bool, list[str]]:
        """Recursively evaluate AND/OR condition groups."""
        operator = conditions.get("operator", "AND").upper()
        rules = conditions.get("rules", [])

        if not rules:
            return True, []

        all_matched_rules = []
        results = []

        for rule in rules:
            if "rules" in rule:
                # Nested condition group
                matched, sub_rules = self._evaluate_condition_group(rule, flat_context)
                results.append(matched)
                if matched:
                    all_matched_rules.extend(sub_rules)
            else:
                # Leaf rule
                matched = self._evaluate_leaf_rule(rule, flat_context)
                results.append(matched)
                if matched:
                    all_matched_rules.append(
                        f"{rule.get('field', '?')} {rule.get('operator', '?')} {rule.get('value', '?')}"
                    )

        if operator == "AND":
            group_matched = all(results)
        elif operator == "OR":
            group_matched = any(results)
        elif operator == "NOT":
            group_matched = not any(results)
        else:
            group_matched = all(results)

        return group_matched, all_matched_rules if group_matched else []

    def _evaluate_leaf_rule(self, rule: dict, flat_context: dict) -> bool:
        """Evaluate a single leaf rule against the flat context."""
        field_path = rule.get("field", "")
        operator = rule.get("operator", "equals")
        expected = rule.get("value")

        actual = flat_context.get(field_path)

        return self._compare(actual, operator, expected)

    def _compare(self, actual: Any, operator: str, expected: Any) -> bool:
        """Compare actual value with expected using the given operator."""
        try:
            if operator == "equals":
                return actual == expected
            elif operator == "not_equals":
                return actual != expected
            elif operator == "contains":
                return str(expected) in str(actual) if actual is not None else False
            elif operator == "not_contains":
                return str(expected) not in str(actual) if actual is not None else True
            elif operator == "starts_with":
                return str(actual or "").startswith(str(expected))
            elif operator == "ends_with":
                return str(actual or "").endswith(str(expected))
            elif operator == "matches":
                return fnmatch.fnmatch(str(actual or ""), str(expected))
            elif operator == "regex":
                return bool(re.search(str(expected), str(actual or "")))
            elif operator == "in":
                if isinstance(expected, list):
                    return actual in expected
                return actual == expected
            elif operator == "not_in":
                if isinstance(expected, list):
                    return actual not in expected
                return actual != expected
            elif operator == "greater_than":
                return float(actual) > float(expected)
            elif operator == "less_than":
                return float(actual) < float(expected)
            elif operator == "greater_than_or_equals":
                return float(actual) >= float(expected)
            elif operator == "less_than_or_equals":
                return float(actual) <= float(expected)
            elif operator == "exists":
                return actual is not None
            elif operator == "not_exists":
                return actual is None
            elif operator == "is_empty":
                return actual is None or actual == "" or actual == []
            elif operator == "is_not_empty":
                return actual is not None and actual != "" and actual != []
        except (TypeError, ValueError):
            return False
        return False

    def _evaluate_legacy_rules(self, rules: dict, flat_context: dict) -> bool:
        """Evaluate legacy rules format (allow_hosts, block_hosts)."""
        url = flat_context.get("request.url", "")
        blocked_hosts = rules.get("block_hosts", [])
        for host in blocked_hosts:
            if host in url:
                return True
        allowed_hosts = rules.get("allow_hosts", [])
        if allowed_hosts:
            for host in allowed_hosts:
                if host in url:
                    return False
            return True  # Not in allowlist = match
        return False


# Singleton instance
engine = PolicyEngine()
