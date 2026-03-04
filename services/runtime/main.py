"""AISR Runtime API (v1 skeleton).

This service provides a single enterprise-facing runtime decision surface.
It orchestrates:
- Detection (content risk)
- Policy (tenant rules)
- Response (actions)
- Control Plane (audit/event ingest)

It is intentionally thin: keep detectors/policies modular, but give buyers one API.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="AISR Runtime API", version="0.2.0")

# Service bases (docker-compose defaults)
DETECTION_BASE = os.getenv("DETECTION_URL", os.getenv("DETECTION_SERVICE_URL", "http://detection:8002"))
POLICY_BASE = os.getenv("POLICY_URL", os.getenv("POLICY_SERVICE_URL", "http://policy:8001"))
RESPONSE_BASE = os.getenv("RESPONSE_URL", "http://response:8003")
CONTROL_PLANE_BASE = os.getenv("CONTROL_PLANE_URL", "http://control-plane:8000")
COMPLIANCE_BASE = os.getenv("COMPLIANCE_URL", "http://compliance:8006")

# Accept both prefixed and legacy secrets. Branding build will set the prefixed ones.
AISHIELDS_POLICY_API_SECRET = os.getenv("AISHIELDS_POLICY_API_SECRET")
CYBERARMOR_POLICY_API_SECRET = os.getenv("CYBERARMOR_POLICY_API_SECRET")
POLICY_API_SECRET = os.getenv("POLICY_API_SECRET")

AISHIELDS_DETECTION_API_SECRET = os.getenv("AISHIELDS_DETECTION_API_SECRET")
CYBERARMOR_DETECTION_API_SECRET = os.getenv("CYBERARMOR_DETECTION_API_SECRET")
DETECTION_API_SECRET = os.getenv("DETECTION_API_SECRET")

AISHIELDS_COMPLIANCE_API_SECRET = os.getenv("AISHIELDS_COMPLIANCE_API_SECRET")
CYBERARMOR_COMPLIANCE_API_SECRET = os.getenv("CYBERARMOR_COMPLIANCE_API_SECRET")
COMPLIANCE_API_SECRET = os.getenv("COMPLIANCE_API_SECRET")


def _pick(*vals: Optional[str]) -> Optional[str]:
    for v in vals:
        if v:
            return v
    return None


policy_secret = _pick(CYBERARMOR_POLICY_API_SECRET, AISHIELDS_POLICY_API_SECRET, POLICY_API_SECRET)
detection_secret = _pick(CYBERARMOR_DETECTION_API_SECRET, AISHIELDS_DETECTION_API_SECRET, DETECTION_API_SECRET)
compliance_secret = _pick(CYBERARMOR_COMPLIANCE_API_SECRET, AISHIELDS_COMPLIANCE_API_SECRET, COMPLIANCE_API_SECRET)


class RuntimeRequest(BaseModel):
    tenant_id: str = "default"
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RuntimeDecision(BaseModel):
    request_id: str
    decision: str  # allow | redact | block
    reasons: List[str] = Field(default_factory=list)
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    risk: Dict[str, Any] = Field(default_factory=dict)
    evidence_snapshot: Optional[Dict[str, Any]] = None


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "aisr-runtime",
        "time": time.time(),
    }


@app.post("/runtime/evaluate", response_model=RuntimeDecision)
async def evaluate(req: RuntimeRequest, x_api_key: Optional[str] = Header(default=None)) -> RuntimeDecision:
    # Correlation ID (prefer the gateway-assigned request_id if present)
    request_id = str(req.metadata.get("request_id") or "").strip() or str(uuid4())
    req.metadata["request_id"] = request_id

    """Evaluate a runtime request.

    Auth:
      - In v1 we accept the upstream gateway/proxy key header if present.
      - Production: validate via control-plane tenant/API key.
    """

    # 1) Detection
    det_headers: Dict[str, str] = {"Content-Type": "application/json"}
    if detection_secret:
        det_headers["x-api-key"] = detection_secret

    async with httpx.AsyncClient(timeout=10.0) as client:
        det = await client.post(
            f"{DETECTION_BASE}/scan",
            headers=det_headers,
            json={"tenant_id": req.tenant_id, "content": req.content},
        )

    if det.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Detection error: {det.status_code}")

    detj = det.json()
    findings = detj.get("findings", [])

    # 2) Policy (best-effort)
    # If policy is unreachable or doesn't have /evaluate, we don't fail the request.
    pol_headers: Dict[str, str] = {"Content-Type": "application/json"}
    if policy_secret:
        pol_headers["x-api-key"] = policy_secret
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{POLICY_BASE}/evaluate",
                headers=pol_headers,
                json={
                    "tenant_id": req.tenant_id,
                    "context": {
                        "request": {
                            "url": req.metadata.get("url", ""),
                            "method": req.metadata.get("method", ""),
                            "host": req.metadata.get("host", ""),
                            "headers": req.metadata.get("headers", {}),
                            "body_snippet": (req.content or "")[:2048],
                        },
                        "user": {"client_ip": req.metadata.get("client_ip", "")},
                    },
                },
            )
    except Exception:
        pass

    # 3) Decide
    decision = "allow"
    reasons: List[str] = []
    actions: List[Dict[str, Any]] = []

    # Simple decisioning for v1: block if any finding severity is high
    for f in findings:
        sev = (f.get("severity") or "").lower()
        if sev in {"high", "critical"}:
            decision = "block"
            reasons.append(f.get("type") or "high_severity_finding")

    if decision == "block":
        actions.append({"kind": "block", "target": "ai_request"})

    # 4) Act (delegate to response orchestrator)
    if actions:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                f"{RESPONSE_BASE}/respond",
                json={
                    "tenant_id": req.tenant_id,
                    "source": "aisr-runtime",
                    "severity": "high" if decision == "block" else "low",
                    "description": "AISR runtime decision",
                    "actions": actions,
                },
            )

    # 5) Evidence snapshot (best-effort)
    evidence_snapshot: Optional[Dict[str, Any]] = None
    if decision != "allow":
        try:
            comp_headers: Dict[str, str] = {"Content-Type": "application/json"}
            if compliance_secret:
                comp_headers["x-api-key"] = compliance_secret

            evidence = {
                "runtime_decisions": {
                    "last": {
                        "request_id": request_id,
                        "decision": decision,
                        "reasons": reasons,
                        "findings": findings,
                        "metadata": req.metadata,
                        "ts": time.time(),
                    }
                }
            }
            async with httpx.AsyncClient(timeout=5.0) as client:
                # Store evidence per-request for perfect end-to-end traceability.
                ev = await client.post(
                    f"{COMPLIANCE_BASE}/evidence/{req.tenant_id}/{request_id}",
                    headers=comp_headers,
                    json={"evidence": evidence},
                )
                rep = await client.post(
                    f"{COMPLIANCE_BASE}/assess/{req.tenant_id}/{request_id}",
                    headers=comp_headers,
                    json={"framework": None, "evidence": evidence},
                )
                evidence_snapshot = {
                    "request_id": request_id,
                    "evidence_result": ev.json() if ev.status_code < 400 else {"status": ev.status_code},
                    "assessment_result": rep.json() if rep.status_code < 400 else {"status": rep.status_code},
                }
        except Exception:
            evidence_snapshot = None

    # 6) Prove (best-effort telemetry ingest)
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"{CONTROL_PLANE_BASE}/incidents/ingest",
                json={
                    "tenant_id": req.tenant_id,
                    "request_id": request_id,
                    "event_type": "runtime_decision",
                    "decision": decision,
                    "reasons": reasons,
                    "findings": findings,
                    "metadata": req.metadata,
                    "evidence_snapshot": evidence_snapshot,
                    "ts": time.time(),
                },
            )
    except Exception:
        pass

    return RuntimeDecision(
        request_id=request_id,
        decision=decision,
        reasons=reasons,
        actions=actions,
        risk={"findings": len(findings)},
        evidence_snapshot=evidence_snapshot,
    )
