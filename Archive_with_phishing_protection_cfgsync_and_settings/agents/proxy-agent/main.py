import logging
import os
from dataclasses import dataclass
from typing import Dict, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("proxy_agent")

POLICY_SERVICE_URL = os.getenv("POLICY_SERVICE_URL", "http://policy:8001")
PROXY_AGENT_API_SECRET = os.getenv("PROXY_AGENT_API_SECRET", "change-me-proxy")
POLICY_API_KEY = os.getenv("POLICY", "change-me-policy")

headers = {"x-api-key": POLICY_API_KEY}

def require_api_key(api_key: str | None = Header(default=None, alias="x-api-key")):
    if api_key != PROXY_AGENT_API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


@dataclass
class CachedPolicy:
    tenant_id: str
    name: str
    rules: dict


class PolicyCache:
    def __init__(self):
        self.cache: dict[str, CachedPolicy] = {}

    def get(self, tenant_id: str, name: str) -> Optional[CachedPolicy]:
        return self.cache.get(f"{tenant_id}:{name}")

    def set(self, policy: CachedPolicy):
        self.cache[f"{policy.tenant_id}:{policy.name}"] = policy


cache = PolicyCache()
local_blocks: Dict[str, set[str]] = {}

app = FastAPI(title="CyberArmor Proxy Agent", version="0.1.1")


class DecisionRequest(BaseModel):
    tenant_id: str
    url: str


class DecisionResponse(BaseModel):
    decision: str
    policy_applied: Optional[str]
    reason: Optional[str] = None


class BlockAction(BaseModel):
    tenant_id: str
    target: str


async def fetch_policy(tenant_id: str, name: str) -> Optional[CachedPolicy]:
    url = f"{POLICY_SERVICE_URL}/policies/{tenant_id}/{name}"
    try:
        async with httpx.AsyncClient(timeout=5.0,headers=headers) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                policy = CachedPolicy(tenant_id=tenant_id, name=name, rules=data.get("rules", {}))
                cache.set(policy)
                return policy
            logger.warning("policy fetch failed status=%s url=%s", resp.status_code, url)
    except Exception as exc:
        logger.error("policy fetch error tenant=%s name=%s err=%s", tenant_id, name, exc)
    return cache.get(tenant_id, name)


def evaluate_request(url: str, tenant_id: str) -> DecisionResponse:
    # Local blocklist first.
    blocks = local_blocks.get(tenant_id, set())
    for blocked in blocks:
        if blocked in url:
            return DecisionResponse(decision="deny", policy_applied="local-block", reason=f"blocked={blocked}")

    policy = cache.get(tenant_id, "proxy-default")
    allowed_hosts = policy.rules.get("allow_hosts", []) if policy else []
    for host in allowed_hosts:
        if host in url:
            return DecisionResponse(decision="allow", policy_applied=policy.name if policy else None)
    return DecisionResponse(decision="deny", policy_applied=policy.name if policy else None, reason="not in allowlist")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/policy/refresh")
async def refresh_policy(tenant_id: str, name: str = "proxy-default", _: None = Depends(require_api_key)):
    policy = await fetch_policy(tenant_id, name)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found upstream")
    return {"status": "cached", "policy": policy.rules}


@app.post("/decision", response_model=DecisionResponse)
async def decision(body: DecisionRequest, _: None = Depends(require_api_key)):
    if not cache.get(body.tenant_id, "proxy-default"):
        await fetch_policy(body.tenant_id, "proxy-default")
    return evaluate_request(body.url, body.tenant_id)

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
