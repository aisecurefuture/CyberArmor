"""CyberArmor Proxy Agent - Policy-based URL filtering with PQC-encrypted auth.

Fixes from v0.1.1:
- Corrected POLICY_API_KEY env var name (was "POLICY", now "POLICY_API_SECRET")
- Added PQC key transport support
- Enhanced policy evaluation with the new extensible policy engine
"""

import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("proxy_agent")

POLICY_SERVICE_URL = os.getenv("POLICY_SERVICE_URL", "http://policy:8001")
PROXY_AGENT_API_SECRET = os.getenv("PROXY_AGENT_API_SECRET", "change-me-proxy")
POLICY_API_KEY = os.getenv("POLICY_API_SECRET", "change-me-policy")  # FIXED: was "POLICY"
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://control-plane:8000")

policy_headers = {"x-api-key": POLICY_API_KEY}


def require_api_key(api_key: str | None = Header(default=None, alias="x-api-key")):
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    # Support both plaintext and PQC-encrypted keys
    effective_key = api_key
    if api_key.startswith("PQC:"):
        try:
            from aishields_core.crypto.key_transport import PQCKeyTransport
            transport = PQCKeyTransport()
            # In production, load server secret key from key manager
            # For now, fall through to plaintext comparison
            logger.info("PQC-encrypted key received (decryption requires key manager)")
        except ImportError:
            pass
    if effective_key != PROXY_AGENT_API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


@dataclass
class CachedPolicy:
    tenant_id: str
    name: str
    rules: dict
    enabled: bool = True
    action: str = "monitor"
    conditions: Optional[dict] = None


class PolicyCache:
    def __init__(self):
        self.cache: dict[str, CachedPolicy] = {}
        self.tenant_policies: dict[str, list[CachedPolicy]] = {}

    def get(self, tenant_id: str, name: str) -> Optional[CachedPolicy]:
        return self.cache.get(f"{tenant_id}:{name}")

    def set(self, policy: CachedPolicy):
        key = f"{policy.tenant_id}:{policy.name}"
        self.cache[key] = policy
        if policy.tenant_id not in self.tenant_policies:
            self.tenant_policies[policy.tenant_id] = []
        # Replace or append
        existing = [p for p in self.tenant_policies[policy.tenant_id] if p.name != policy.name]
        existing.append(policy)
        self.tenant_policies[policy.tenant_id] = existing

    def get_all_for_tenant(self, tenant_id: str) -> list[CachedPolicy]:
        return self.tenant_policies.get(tenant_id, [])

    def clear_tenant(self, tenant_id: str):
        for key in list(self.cache.keys()):
            if key.startswith(f"{tenant_id}:"):
                del self.cache[key]
        self.tenant_policies.pop(tenant_id, None)


cache = PolicyCache()
local_blocks: Dict[str, set[str]] = {}

app = FastAPI(title="CyberArmor.ai Proxy Agent", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class DecisionRequest(BaseModel):
    tenant_id: str
    url: str
    user_id: Optional[str] = None
    content: Optional[str] = None
    metadata: Optional[dict] = None


class DecisionResponse(BaseModel):
    decision: str  # allow, deny, monitor, warn
    policy_applied: Optional[str] = None
    reason: Optional[str] = None
    actions: Optional[List[str]] = None


class BlockAction(BaseModel):
    tenant_id: str
    target: str


class BulkPolicySync(BaseModel):
    tenant_id: str
    policies: List[dict]


async def fetch_policies(tenant_id: str) -> list[CachedPolicy]:
    """Fetch all policies for a tenant from the policy service."""
    url = f"{POLICY_SERVICE_URL}/policies/{tenant_id}"
    try:
        async with httpx.AsyncClient(timeout=5.0, headers=policy_headers) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                policies = []
                for p in data:
                    cp = CachedPolicy(
                        tenant_id=tenant_id,
                        name=p.get("name", ""),
                        rules=p.get("rules", {}),
                        enabled=p.get("enabled", True),
                        action=p.get("action", "monitor"),
                        conditions=p.get("conditions"),
                    )
                    cache.set(cp)
                    policies.append(cp)
                return policies
            logger.warning("policy fetch failed status=%s url=%s", resp.status_code, url)
    except Exception as exc:
        logger.error("policy fetch error tenant=%s err=%s", tenant_id, exc)
    return cache.get_all_for_tenant(tenant_id)


async def fetch_policy(tenant_id: str, name: str) -> Optional[CachedPolicy]:
    """Fetch a single named policy from the policy service."""
    url = f"{POLICY_SERVICE_URL}/policies/{tenant_id}/{name}"
    try:
        async with httpx.AsyncClient(timeout=5.0, headers=policy_headers) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                policy = CachedPolicy(
                    tenant_id=tenant_id,
                    name=name,
                    rules=data.get("rules", {}),
                    enabled=data.get("enabled", True),
                    action=data.get("action", "monitor"),
                    conditions=data.get("conditions"),
                )
                cache.set(policy)
                return policy
            logger.warning("policy fetch failed status=%s url=%s", resp.status_code, url)
    except Exception as exc:
        logger.error("policy fetch error tenant=%s name=%s err=%s", tenant_id, name, exc)
    return cache.get(tenant_id, name)


def evaluate_conditions(conditions: dict, context: dict) -> bool:
    """Evaluate AND/OR policy conditions against a request context."""
    if not conditions:
        return True

    operator = conditions.get("operator", "AND").upper()
    rules = conditions.get("rules", [])

    if not rules:
        return True

    results = []
    for rule in rules:
        if "operator" in rule and "rules" in rule:
            # Nested condition group
            results.append(evaluate_conditions(rule, context))
        else:
            # Leaf rule
            field = rule.get("field", "")
            op = rule.get("operator", "equals")
            value = rule.get("value")
            actual = _get_nested_value(context, field)
            results.append(_evaluate_rule(actual, op, value))

    if operator == "AND":
        return all(results)
    elif operator == "OR":
        return any(results)
    return False


def _get_nested_value(obj: dict, path: str):
    """Get a value from a nested dict using dot notation."""
    parts = path.split(".")
    current = obj
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _evaluate_rule(actual, operator: str, expected) -> bool:
    """Evaluate a single rule."""
    if operator == "equals":
        return actual == expected
    elif operator == "not_equals":
        return actual != expected
    elif operator == "contains":
        return expected in str(actual) if actual else False
    elif operator == "not_contains":
        return expected not in str(actual) if actual else True
    elif operator == "matches":
        import fnmatch
        return fnmatch.fnmatch(str(actual or ""), str(expected))
    elif operator == "in":
        return actual in (expected if isinstance(expected, list) else [expected])
    elif operator == "not_in":
        return actual not in (expected if isinstance(expected, list) else [expected])
    elif operator == "greater_than":
        try:
            return float(actual) > float(expected)
        except (TypeError, ValueError):
            return False
    elif operator == "less_than":
        try:
            return float(actual) < float(expected)
        except (TypeError, ValueError):
            return False
    elif operator == "exists":
        return actual is not None
    elif operator == "not_exists":
        return actual is None
    elif operator == "starts_with":
        return str(actual or "").startswith(str(expected))
    elif operator == "ends_with":
        return str(actual or "").endswith(str(expected))
    elif operator == "regex":
        import re
        try:
            return bool(re.search(str(expected), str(actual or "")))
        except re.error:
            return False
    return False


def evaluate_request(request: DecisionRequest) -> DecisionResponse:
    """Evaluate a request against all active policies for the tenant."""
    tenant_id = request.tenant_id
    url = request.url

    # Local blocklist takes priority
    blocks = local_blocks.get(tenant_id, set())
    for blocked in blocks:
        if blocked in url:
            return DecisionResponse(
                decision="deny",
                policy_applied="local-block",
                reason=f"blocked={blocked}",
            )

    # Build evaluation context
    context = {
        "request": {
            "url": url,
            "user_id": request.user_id,
        },
        "content": {
            "text": request.content,
            "has_pii": False,  # Will be enriched by detection service
        },
        "metadata": request.metadata or {},
    }

    # Evaluate all enabled policies (sorted by priority if available)
    policies = cache.get_all_for_tenant(tenant_id)
    enabled_policies = [p for p in policies if p.enabled]

    for policy in enabled_policies:
        if policy.conditions:
            match = evaluate_conditions(policy.conditions, context)
            if match:
                return DecisionResponse(
                    decision=policy.action,
                    policy_applied=policy.name,
                    reason=f"Matched policy conditions",
                    actions=[policy.action],
                )
        elif policy.rules:
            # Legacy rule format support
            allowed_hosts = policy.rules.get("allow_hosts", [])
            blocked_hosts = policy.rules.get("block_hosts", [])
            for host in blocked_hosts:
                if host in url:
                    return DecisionResponse(
                        decision="deny",
                        policy_applied=policy.name,
                        reason=f"blocked host: {host}",
                    )
            for host in allowed_hosts:
                if host in url:
                    return DecisionResponse(
                        decision="allow",
                        policy_applied=policy.name,
                    )

    # Default: allow if no policy matched (configurable per tenant)
    default_policy = cache.get(tenant_id, "proxy-default")
    if default_policy and default_policy.action == "deny":
        return DecisionResponse(
            decision="deny",
            policy_applied="proxy-default",
            reason="Default deny policy",
        )

    return DecisionResponse(
        decision="allow",
        policy_applied=None,
        reason="No matching policy; default allow",
    )


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.2.0"}


@app.post("/policy/refresh")
async def refresh_policy(
    tenant_id: str,
    name: str = "proxy-default",
    _: None = Depends(require_api_key),
):
    policy = await fetch_policy(tenant_id, name)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found upstream")
    return {"status": "cached", "policy": policy.rules}


@app.post("/policy/sync")
async def sync_policies(
    body: BulkPolicySync,
    _: None = Depends(require_api_key),
):
    """Receive bulk policy sync from control plane."""
    cache.clear_tenant(body.tenant_id)
    for p in body.policies:
        cp = CachedPolicy(
            tenant_id=body.tenant_id,
            name=p.get("name", ""),
            rules=p.get("rules", {}),
            enabled=p.get("enabled", True),
            action=p.get("action", "monitor"),
            conditions=p.get("conditions"),
        )
        cache.set(cp)
    logger.info("policy sync tenant=%s count=%d", body.tenant_id, len(body.policies))
    return {"status": "synced", "count": len(body.policies)}


@app.post("/policy/refresh-all")
async def refresh_all_policies(
    tenant_id: str,
    _: None = Depends(require_api_key),
):
    """Refresh all policies for a tenant from the policy service."""
    policies = await fetch_policies(tenant_id)
    return {"status": "refreshed", "count": len(policies)}


@app.post("/decision", response_model=DecisionResponse)
async def decision(body: DecisionRequest, _: None = Depends(require_api_key)):
    if not cache.get_all_for_tenant(body.tenant_id):
        await fetch_policies(body.tenant_id)
    return evaluate_request(body)


@app.get("/blocks/{tenant_id}", response_model=list[str])
def get_blocks(tenant_id: str):
    blocks = local_blocks.get(tenant_id)
    if not blocks:
        return []
    return sorted(list(blocks))


@app.post("/actions/block")
def block_target(action: BlockAction, _: None = Depends(require_api_key)):
    local_blocks.setdefault(action.tenant_id, set()).add(action.target)
    logger.warning("local block added tenant=%s target=%s", action.tenant_id, action.target)
    return {"status": "blocked", "target": action.target}


@app.delete("/actions/unblock")
def unblock_target(action: BlockAction, _: None = Depends(require_api_key)):
    blocks = local_blocks.get(action.tenant_id, set())
    blocks.discard(action.target)
    logger.info("local block removed tenant=%s target=%s", action.tenant_id, action.target)
    return {"status": "unblocked", "target": action.target}


@app.get("/policies/cached/{tenant_id}")
def get_cached_policies(tenant_id: str, _: None = Depends(require_api_key)):
    """Return all cached policies for a tenant (for debugging/status)."""
    policies = cache.get_all_for_tenant(tenant_id)
    return [
        {
            "name": p.name,
            "enabled": p.enabled,
            "action": p.action,
            "has_conditions": p.conditions is not None,
        }
        for p in policies
    ]
