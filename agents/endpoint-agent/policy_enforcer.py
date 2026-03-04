"""Local Policy Enforcement Engine for AIShields Endpoint Agent.

Receives policies from control plane, evaluates events against AND/OR
conditions, and takes action (monitor, warn, block). Caches policies
locally in SQLite for offline operation.
"""

import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("policy_enforcer")

CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8000")
POLICY_SERVICE_URL = os.getenv("POLICY_SERVICE_URL", "http://localhost:8001")
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")
TENANT_ID = os.getenv("TENANT_ID", "demo")
SYNC_INTERVAL_S = int(os.getenv("POLICY_SYNC_INTERVAL", "60"))
CACHE_DIR = Path(os.getenv("AISHIELDS_CACHE_DIR", os.path.expanduser("~/.aishields")))


@dataclass
class PolicyAction:
    action: str  # monitor, warn, block
    policy_name: str
    policy_id: str
    reason: str
    matched_rules: List[str] = field(default_factory=list)


@dataclass
class EnforcementResult:
    allowed: bool
    actions: List[PolicyAction] = field(default_factory=list)
    highest_action: str = "allow"


class PolicyEnforcer:
    """Evaluates events against cached policies with AND/OR conditions."""

    def __init__(self):
        self.policies: List[dict] = []
        self.db_path = CACHE_DIR / "policy_cache.db"
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._load_cached_policies()

    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY, name TEXT, tenant_id TEXT,
                enabled INTEGER, action TEXT, priority INTEGER,
                conditions TEXT, rules TEXT, version TEXT,
                updated_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, event_type TEXT, policy_id TEXT,
                policy_name TEXT, action_taken TEXT, details TEXT
            )
        """)
        conn.commit()
        conn.close()

    def _load_cached_policies(self):
        try:
            conn = sqlite3.connect(str(self.db_path))
            rows = conn.execute(
                "SELECT id, name, tenant_id, enabled, action, priority, conditions, rules, version FROM policies WHERE tenant_id=?",
                (TENANT_ID,)
            ).fetchall()
            self.policies = []
            for r in rows:
                self.policies.append({
                    "id": r[0], "name": r[1], "tenant_id": r[2],
                    "enabled": bool(r[3]), "action": r[4], "priority": r[5],
                    "conditions": json.loads(r[6]) if r[6] else None,
                    "rules": json.loads(r[7]) if r[7] else {},
                    "version": r[8],
                })
            conn.close()
            logger.info("Loaded %d cached policies", len(self.policies))
        except Exception as e:
            logger.warning("Failed to load cached policies: %s", e)

    async def sync_policies(self):
        """Fetch policies from control plane and cache locally."""
        headers = {"x-api-key": AGENT_API_KEY}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{POLICY_SERVICE_URL}/policies/{TENANT_ID}/export",
                    headers=headers,
                )
                if resp.status_code == 200:
                    policies = resp.json()
                    self._cache_policies(policies)
                    self.policies = policies
                    logger.info("Synced %d policies from control plane", len(policies))
                else:
                    logger.warning("Policy sync failed: %s", resp.status_code)
        except Exception as e:
            logger.warning("Policy sync error: %s", e)

    def _cache_policies(self, policies: List[dict]):
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.execute("DELETE FROM policies WHERE tenant_id=?", (TENANT_ID,))
            for p in policies:
                conn.execute(
                    "INSERT OR REPLACE INTO policies (id,name,tenant_id,enabled,action,priority,conditions,rules,version,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (p["id"], p["name"], TENANT_ID, int(p.get("enabled", True)),
                     p.get("action", "monitor"), p.get("priority", 100),
                     json.dumps(p.get("conditions")), json.dumps(p.get("rules", {})),
                     p.get("version", ""), datetime.now(timezone.utc).isoformat()),
                )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("Failed to cache policies: %s", e)

    def evaluate(self, context: Dict[str, Any]) -> EnforcementResult:
        """Evaluate an event context against all enabled policies."""
        actions = []
        enabled = sorted(
            [p for p in self.policies if p.get("enabled", True)],
            key=lambda p: p.get("priority", 100)
        )
        flat = self._flatten_context(context)

        for policy in enabled:
            conditions = policy.get("conditions")
            matched = False
            matched_rules = []

            if conditions:
                matched, matched_rules = self._eval_group(conditions, flat)
            elif policy.get("rules"):
                matched = self._eval_legacy(policy["rules"], flat)

            if matched:
                pa = PolicyAction(
                    action=policy.get("action", "monitor"),
                    policy_name=policy.get("name", ""),
                    policy_id=policy.get("id", ""),
                    reason=f"Matched {len(matched_rules)} rule(s)",
                    matched_rules=matched_rules,
                )
                actions.append(pa)
                self._audit_log(pa, context)

        highest = "allow"
        if any(a.action == "block" for a in actions):
            highest = "block"
        elif any(a.action == "warn" for a in actions):
            highest = "warn"
        elif any(a.action == "monitor" for a in actions):
            highest = "monitor"

        return EnforcementResult(
            allowed=highest != "block",
            actions=actions,
            highest_action=highest,
        )

    def _eval_group(self, cond: dict, flat: dict) -> tuple:
        op = cond.get("operator", "AND").upper()
        rules = cond.get("rules", [])
        if not rules:
            return True, []
        results, all_matched = [], []
        for rule in rules:
            if "rules" in rule:
                m, mr = self._eval_group(rule, flat)
                results.append(m)
                if m:
                    all_matched.extend(mr)
            else:
                m = self._eval_leaf(rule, flat)
                results.append(m)
                if m:
                    all_matched.append(f"{rule.get('field','?')} {rule.get('operator','?')} {rule.get('value','?')}")
        group_match = all(results) if op == "AND" else any(results)
        return group_match, all_matched if group_match else []

    def _eval_leaf(self, rule: dict, flat: dict) -> bool:
        actual = flat.get(rule.get("field", ""))
        expected = rule.get("value")
        op = rule.get("operator", "equals")
        try:
            if op == "equals": return actual == expected
            if op == "not_equals": return actual != expected
            if op == "contains": return str(expected) in str(actual or "")
            if op == "not_contains": return str(expected) not in str(actual or "")
            if op == "matches":
                import fnmatch
                return fnmatch.fnmatch(str(actual or ""), str(expected))
            if op == "in": return actual in (expected if isinstance(expected, list) else [expected])
            if op == "exists": return actual is not None
            if op == "regex":
                import re
                return bool(re.search(str(expected), str(actual or "")))
        except Exception:
            return False
        return False

    def _eval_legacy(self, rules: dict, flat: dict) -> bool:
        url = flat.get("request.url", "")
        for host in rules.get("block_hosts", []):
            if host in str(url):
                return True
        return False

    def _flatten_context(self, ctx: dict) -> dict:
        flat = {}
        for prefix, section in ctx.items():
            if isinstance(section, dict):
                for k, v in section.items():
                    flat[f"{prefix}.{k}"] = v
            else:
                flat[prefix] = section
        return flat

    def _audit_log(self, action: PolicyAction, context: dict):
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.execute(
                "INSERT INTO audit_log (timestamp, event_type, policy_id, policy_name, action_taken, details) VALUES (?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), "policy_match",
                 action.policy_id, action.policy_name, action.action,
                 json.dumps({"reason": action.reason, "rules": action.matched_rules})),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning("Audit log write failed: %s", e)
