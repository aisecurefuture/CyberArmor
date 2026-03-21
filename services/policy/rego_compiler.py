"""Rego Compiler – converts CyberArmor JSON policy conditions to OPA Rego modules.

This compiler is used to materialise each CyberArmor policy as a standalone
Rego module that can be pushed to OPA.  The generated modules are intentionally
simple: they declare a single ``matched`` rule that mirrors the JSON conditions.

The base evaluation logic lives in ``rego/cyberarmor_base.rego`` and is
loaded once at startup.  Per-policy modules generated here are only needed
when operators want to author Rego directly rather than via the JSON condition
builder – in that workflow the generated Rego acts as a scaffold.

For the primary evaluation path the Python service passes all policies as
JSON *data* to OPA and evaluates them via the base Rego module.  This compiler
is therefore called on every policy upsert to keep OPA in sync, and its output
is pushed via ``opa_client.put_policy()``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Field path → Rego reference helper
# ---------------------------------------------------------------------------


def _field_ref(field_path: str) -> str:
    """Convert a dot-notation path to an OPA ``input.context`` lookup.

    "request.url"  →  input.context["request.url"]

    The flat context dict uses dot-notation keys (as produced by
    ``EvaluationContext.to_flat_dict()``), so we keep the whole dotted key
    as a single bracket-quoted lookup rather than splitting on dots.
    """
    escaped = field_path.replace('"', '\\"')
    return f'input.context["{escaped}"]'


# ---------------------------------------------------------------------------
# Value → Rego literal helper
# ---------------------------------------------------------------------------


def _rego_literal(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, list):
        items = ", ".join(_rego_literal(v) for v in value)
        return f"[{items}]"
    # Fallback: JSON encode
    return json.dumps(value)


# ---------------------------------------------------------------------------
# Leaf operator → Rego expression
# ---------------------------------------------------------------------------


def _leaf_expr(field_path: str, operator: str, value: Any) -> str:
    ref = _field_ref(field_path)
    val = _rego_literal(value)

    _map = {
        "equals":                  f"{ref} == {val}",
        "not_equals":              f"{ref} != {val}",
        "contains":                f"contains({ref}, {val})",
        "not_contains":            f"not contains({ref}, {val})",
        "starts_with":             f"startswith({ref}, {val})",
        "ends_with":               f"endswith({ref}, {val})",
        "matches":                 f"glob.match({val}, [], {ref})",
        "regex":                   f"regex.match({val}, {ref})",
        "in":                      f"{ref} in {val}",
        "not_in":                  f"not {ref} in {val}",
        "greater_than":            f"{ref} > {val}",
        "less_than":               f"{ref} < {val}",
        "greater_than_or_equals":  f"{ref} >= {val}",
        "less_than_or_equals":     f"{ref} <= {val}",
        "exists":                  f"_ := {ref}",
        "not_exists":              f"not {ref}",
        "is_empty":                f"count({ref}) == 0",
        "is_not_empty":            f"count({ref}) > 0",
    }
    return _map.get(operator, f"{ref} == {val}")


# ---------------------------------------------------------------------------
# Condition group → list of Rego body lines
# ---------------------------------------------------------------------------


def _group_to_bodies(
    conditions: Dict[str, Any],
) -> List[List[str]]:
    """Return a list of rule *bodies* (each body is a list of Rego lines).

    AND → one body containing all leaf/sub-group lines (conjunction).
    OR  → one body per alternative (disjunction via multiple rule heads).
    NOT → one body with negated lines.
    """
    operator = str(conditions.get("operator", "AND")).upper()
    rules: List[Dict[str, Any]] = conditions.get("rules", [])

    if not rules:
        return [[]]  # empty body → always true

    if operator == "AND":
        body: List[str] = []
        for rule in rules:
            if "rules" in rule:
                sub_bodies = _group_to_bodies(rule)
                # For AND we can only inline the first sub-body;
                # nested OR sub-groups need a helper rule (see note below).
                if sub_bodies:
                    body.extend(sub_bodies[0])
            else:
                field = rule.get("field", "")
                op = rule.get("operator", "equals")
                val = rule.get("value")
                if field:
                    body.append(_leaf_expr(field, op, val))
        return [body]

    if operator == "OR":
        all_bodies: List[List[str]] = []
        for rule in rules:
            if "rules" in rule:
                all_bodies.extend(_group_to_bodies(rule))
            else:
                field = rule.get("field", "")
                op = rule.get("operator", "equals")
                val = rule.get("value")
                if field:
                    all_bodies.append([_leaf_expr(field, op, val)])
        return all_bodies if all_bodies else [[]]

    if operator == "NOT":
        body = []
        for rule in rules:
            if "rules" in rule:
                sub_bodies = _group_to_bodies(rule)
                if sub_bodies:
                    body.extend(f"not ({line})" for line in sub_bodies[0])
            else:
                field = rule.get("field", "")
                op = rule.get("operator", "equals")
                val = rule.get("value")
                if field:
                    body.append(f"not ({_leaf_expr(field, op, val)})")
        return [body]

    # Default: treat as AND
    return _group_to_bodies({**conditions, "operator": "AND"})


# ---------------------------------------------------------------------------
# Identifier sanitisation
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r"[^a-zA-Z0-9_]")


def _safe_ident(s: str) -> str:
    return _IDENT_RE.sub("_", s)


# ---------------------------------------------------------------------------
# Public compiler
# ---------------------------------------------------------------------------


class RegoCompiler:
    """Compiles a CyberArmor policy (with JSON conditions) into a Rego module.

    The generated module is self-contained and declares:
      - ``package cyberarmor.p<safe_policy_id>``
      - ``matched``   – true when the policy conditions are satisfied
      - ``action``    – string literal (block/warn/monitor/allow)
      - ``priority``  – integer literal
      - ``result``    – object combining the above with policy metadata

    Operators can override the generated Rego by calling
    ``POST /policies/import`` with ``format=rego``.
    """

    def compile(
        self,
        policy_id: str,
        policy_name: str,
        tenant_id: str,
        action: str,
        conditions: Optional[Dict[str, Any]],
        priority: int = 100,
        compliance_frameworks: Optional[List[str]] = None,
    ) -> str:
        safe_id = _safe_ident(policy_id)
        pkg = f"cyberarmor.p{safe_id}"

        frameworks_literal = _rego_literal(compliance_frameworks or [])

        header = [
            f"# Auto-generated by CyberArmor RegoCompiler",
            f"# Policy  : {policy_name}",
            f"# Tenant  : {tenant_id}",
            f"# Action  : {action}  |  Priority: {priority}",
            f"",
            f"package {pkg}",
            f"",
            f"import future.keywords.if",
            f"import future.keywords.in",
            f"",
            f'default matched := false',
            f'default action   := "{action}"',
            f'default priority := {priority}',
            f"",
        ]

        body_lines: List[str]

        if conditions is None:
            # No conditions – always matches
            matched_rules = ["matched := true"]
        else:
            bodies = _group_to_bodies(conditions)
            matched_rules = []
            for body in bodies:
                if not body:
                    matched_rules.append("matched := true")
                else:
                    rule_lines = ["matched if {"]
                    rule_lines.extend(f"    {line}" for line in body)
                    rule_lines.append("}")
                    matched_rules.append("\n".join(rule_lines))

        result_rule = [
            "",
            "result := {",
            f'    "policy_id":             "{policy_id}",',
            f'    "policy_name":           "{policy_name}",',
            f'    "action":                action,',
            f'    "priority":              priority,',
            f'    "matched":               matched,',
            f'    "compliance_frameworks": {frameworks_literal},',
            "}",
        ]

        parts = header + matched_rules + result_rule
        return "\n".join(parts) + "\n"
