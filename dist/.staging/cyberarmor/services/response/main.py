import logging
import os
from datetime import datetime, timezone
from typing import List, Optional

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("response_service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

PROXY_AGENT_URL = os.getenv("PROXY_AGENT_URL", "http://proxy-agent:8010")
WEBHOOK_URL = os.getenv("RESPONSE_WEBHOOK_URL", "")

app = FastAPI(title="CyberArmor Response Orchestrator", version="0.1.1")


class ResponseAction(BaseModel):
    kind: str  # block|redirect|quarantine|notify|ticket|webhook
    target: Optional[str] = None
    message: Optional[str] = None


class Incident(BaseModel):
    tenant_id: str
    source: str
    severity: str
    description: str
    actions: List[ResponseAction] = []
    detected_at: datetime = datetime.now(timezone.utc)


@app.get("/health")
def health():
    return {"status": "ok"}


async def dispatch_actions(incident: Incident):
    async with httpx.AsyncClient(timeout=5.0) as client:
        for action in incident.actions:
            if action.kind == "block" and action.target:
                try:
                    await client.post(f"{PROXY_AGENT_URL}/actions/block", json={"tenant_id": incident.tenant_id, "target": action.target})
                    logger.info("block dispatched tenant=%s target=%s", incident.tenant_id, action.target)
                except Exception as exc:
                    logger.error("block dispatch failed tenant=%s target=%s err=%s", incident.tenant_id, action.target, exc)
            if action.kind == "webhook" and WEBHOOK_URL:
                try:
                    await client.post(WEBHOOK_URL, json={"tenant_id": incident.tenant_id, "source": incident.source, "action": action.kind, "target": action.target, "message": action.message})
                except Exception as exc:
                    logger.error("webhook dispatch failed err=%s", exc)


@app.post("/respond")
async def respond(incident: Incident):
    logger.warning(
        "incident tenant=%s source=%s severity=%s actions=%s",
        incident.tenant_id,
        incident.source,
        incident.severity,
        [a.kind for a in incident.actions],
    )
    await dispatch_actions(incident)
    return {"status": "queued", "actions": incident.actions}
