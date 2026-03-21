# CyberArmor Base Policy Evaluation Module
#
# Evaluates an ordered list of CyberArmor policies against a request context.
#
# Input schema (POST /v1/data/cyberarmor/policy):
#   {
#     "input": {
#       "policies": [
#         {
#           "id":                   "uuid",
#           "name":                 "Block PII to External",
#           "enabled":              true,
#           "action":               "block",     # block | warn | monitor | allow
#           "priority":             10,
#           "conditions":           { ... },     # optional; null = always matches
#           "compliance_frameworks": ["SOC2"]
#         }, ...
#       ],
#       "context": {               # flat dot-notation key/value map
#         "request.url":           "https://api.openai.com/v1/chat",
#         "content.has_pii":       true,
#         "content.risk_score":    0.85,
#         "user.department":       "engineering",
#         ...
#       }
#     }
#   }
#
# Output (result of `cyberarmor.policy.matches`):
#   [
#     {
#       "policy_id":              "uuid",
#       "policy_name":            "Block PII to External",
#       "action":                 "block",
#       "priority":               10,
#       "compliance_frameworks":  ["SOC2"]
#     }, ...
#   ]
#   (sorted by priority ascending; the first element is the highest-priority match)
#
# The Python service calls `cyberarmor/policy/matches` and takes `[0]`.

package cyberarmor.policy

# Note: `if`, `in`, and `every` are built-in keywords in OPA v0.42+.
# Do NOT add `import future.keywords.*` — those imports cause a 400 error
# in OPA v0.67+ where those keywords are default and the imports are deprecated.

# ---------------------------------------------------------------------------
# Public rules
# ---------------------------------------------------------------------------

# All matching policies, sorted by priority (lowest number = highest priority).
# Returns an empty array when nothing matches.
matches := sorted_matches if {
    sorted_matches := [m |
        some p in input.policies
        p.enabled == true
        _policy_matches(p, input.context)
        m := {
            "policy_id":             p.id,
            "policy_name":           p.name,
            "action":                p.action,
            "priority":              p.priority,
            "compliance_frameworks": object.get(p, "compliance_frameworks", []),
        }
    ]
}

# Convenience rule: the single highest-priority match (or undefined).
first_match := matches[0] if count(matches) > 0

# ---------------------------------------------------------------------------
# Policy matching
# ---------------------------------------------------------------------------

# A policy with no conditions always matches.
_policy_matches(policy, _ctx) if {
    not policy.conditions
}

_policy_matches(policy, _ctx) if {
    policy.conditions == null
}

# A policy with conditions matches when the root condition group evaluates true.
_policy_matches(policy, ctx) if {
    policy.conditions != null
    _eval_group(policy.conditions, ctx)
}

# ---------------------------------------------------------------------------
# Condition group evaluation  (AND / OR / NOT)
# ---------------------------------------------------------------------------

# AND: every rule/sub-group in the group must match
_eval_group(group, ctx) if {
    group.operator == "AND"
    every rule in group.rules {
        _eval_rule_or_group(rule, ctx)
    }
}

# OR: at least one rule/sub-group must match
_eval_group(group, ctx) if {
    group.operator == "OR"
    some rule in group.rules
    _eval_rule_or_group(rule, ctx)
}

# NOT: none of the rules/sub-groups may match
_eval_group(group, ctx) if {
    group.operator == "NOT"
    count([r | r := group.rules[_]; _eval_rule_or_group(r, ctx)]) == 0
}

# Default operator (no "operator" key) treated as AND
_eval_group(group, ctx) if {
    not group.operator
    every rule in group.rules {
        _eval_rule_or_group(rule, ctx)
    }
}

# ---------------------------------------------------------------------------
# Dispatch: nested group vs leaf rule
# ---------------------------------------------------------------------------

_eval_rule_or_group(node, ctx) if {
    node.rules   # has a nested rules array → treat as a sub-group
    _eval_group(node, ctx)
}

_eval_rule_or_group(node, ctx) if {
    not node.rules   # no nested rules → leaf rule
    _eval_leaf(node, ctx)
}

# ---------------------------------------------------------------------------
# Leaf rule operators
# ---------------------------------------------------------------------------

_eval_leaf(rule, ctx) if {
    rule.operator == "equals"
    ctx[rule.field] == rule.value
}

_eval_leaf(rule, ctx) if {
    rule.operator == "not_equals"
    ctx[rule.field] != rule.value
}

_eval_leaf(rule, ctx) if {
    rule.operator == "contains"
    contains(ctx[rule.field], rule.value)
}

_eval_leaf(rule, ctx) if {
    rule.operator == "not_contains"
    not contains(ctx[rule.field], rule.value)
}

_eval_leaf(rule, ctx) if {
    rule.operator == "starts_with"
    startswith(ctx[rule.field], rule.value)
}

_eval_leaf(rule, ctx) if {
    rule.operator == "ends_with"
    endswith(ctx[rule.field], rule.value)
}

_eval_leaf(rule, ctx) if {
    rule.operator == "matches"
    glob.match(rule.value, [], ctx[rule.field])
}

_eval_leaf(rule, ctx) if {
    rule.operator == "regex"
    regex.match(rule.value, ctx[rule.field])
}

_eval_leaf(rule, ctx) if {
    rule.operator == "in"
    ctx[rule.field] in rule.value
}

_eval_leaf(rule, ctx) if {
    rule.operator == "not_in"
    not ctx[rule.field] in rule.value
}

_eval_leaf(rule, ctx) if {
    rule.operator == "greater_than"
    ctx[rule.field] > rule.value
}

_eval_leaf(rule, ctx) if {
    rule.operator == "less_than"
    ctx[rule.field] < rule.value
}

_eval_leaf(rule, ctx) if {
    rule.operator == "greater_than_or_equals"
    ctx[rule.field] >= rule.value
}

_eval_leaf(rule, ctx) if {
    rule.operator == "less_than_or_equals"
    ctx[rule.field] <= rule.value
}

_eval_leaf(rule, ctx) if {
    rule.operator == "exists"
    _ := ctx[rule.field]
}

_eval_leaf(rule, ctx) if {
    rule.operator == "not_exists"
    not ctx[rule.field]
}

_eval_leaf(rule, ctx) if {
    rule.operator == "is_empty"
    count(ctx[rule.field]) == 0
}

_eval_leaf(rule, ctx) if {
    rule.operator == "is_not_empty"
    count(ctx[rule.field]) > 0
}
