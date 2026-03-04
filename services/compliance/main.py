"""AIShields Compliance Framework Engine — FastAPI Service (port 8006)."""

import os
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from frameworks import list_frameworks, get_framework

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("compliance")

API_SECRET = os.getenv("COMPLIANCE_API_SECRET", "change-me-compliance")

app = FastAPI(title="AIShields Compliance Engine", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# In-memory storage for assessments and evidence
_assessments: Dict[str, list] = {}    # tenant_id -> [AssessmentResult.to_dict()]
_evidence: Dict[str, dict] = {}       # tenant_id -> merged evidence dict

# Request-scoped evidence/assessments for perfect demo traceability.
_evidence_by_request: Dict[str, Dict[str, dict]] = {}      # tenant_id -> request_id -> evidence dict
_assessments_by_request: Dict[str, Dict[str, dict]] = {}   # tenant_id -> request_id -> assessment result

# ── Auth ──────────────────────────────────────────────────
def verify_api_key(x_api_key: str = Header(None)):
    if not API_SECRET or API_SECRET == "change-me-compliance":
        return  # Dev mode — no auth
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="Invalid API key")

# ── Models ────────────────────────────────────────────────
class AssessmentRequest(BaseModel):
    framework: Optional[str] = None  # None = assess all
    evidence: Optional[Dict] = None  # Additional evidence to merge

class EvidenceSubmission(BaseModel):
    evidence: Dict

class FrameworkInfo(BaseModel):
    id: str
    name: str
    version: str

class ControlInfo(BaseModel):
    id: str
    name: str
    description: str
    category: str
    severity: str
    automated: bool

# ── Routes ────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "service": "compliance", "frameworks": len(list_frameworks())}

@app.get("/frameworks", response_model=List[FrameworkInfo])
def get_frameworks(dep=Depends(verify_api_key)):
    """List all supported compliance frameworks."""
    return list_frameworks()

@app.get("/frameworks/{framework_id}/controls", response_model=List[ControlInfo])
def get_framework_controls(framework_id: str, dep=Depends(verify_api_key)):
    """List controls for a specific framework."""
    try:
        fw = get_framework(framework_id)
    except ValueError:
        raise HTTPException(404, f"Framework not found: {framework_id}")
    controls = fw.get_controls()
    return [
        ControlInfo(id=c.id, name=c.name, description=c.description,
                    category=c.category, severity=c.severity, automated=c.automated)
        for c in controls
    ]

@app.post("/assess/{tenant_id}")
def run_assessment(tenant_id: str, req: AssessmentRequest, dep=Depends(verify_api_key)):
    """Run compliance assessment for a tenant.

    If framework is specified, assess only that framework.
    If None, assess all frameworks.
    Merges stored evidence with any evidence in the request.
    """
    # Merge stored evidence with request evidence
    stored = _evidence.get(tenant_id, {})
    merged = {**stored, **(req.evidence or {})}

    if not merged:
        logger.warning("No evidence for tenant %s — results will show all controls failing", tenant_id)

    results = []
    if req.framework:
        try:
            fw = get_framework(req.framework)
        except ValueError:
            raise HTTPException(404, f"Framework not found: {req.framework}")
        result = fw.assess(merged, tenant_id)
        results.append(result.to_dict())
    else:
        for fw_info in list_frameworks():
            fw = get_framework(fw_info["id"])
            result = fw.assess(merged, tenant_id)
            results.append(result.to_dict())

    # Store results
    _assessments.setdefault(tenant_id, [])
    for r in results:
        _assessments[tenant_id].append(r)

    if len(results) == 1:
        return results[0]
    return {
        "tenant_id": tenant_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "frameworks_assessed": len(results),
        "results": results,
    }


@app.post("/assess/{tenant_id}/{request_id}")
def run_assessment_for_request(tenant_id: str, request_id: str, req: AssessmentRequest, dep=Depends(verify_api_key)):
    """Run compliance assessment for a specific request_id.

    This enables end-to-end traceability in demos: one request -> one decision -> one evidence -> one report.
    Evidence is pulled from request-scoped evidence storage and merged with optional evidence in the request.
    """
    stored = _evidence_by_request.get(tenant_id, {}).get(request_id, {})
    merged = {**stored, **(req.evidence or {})}

    results = []
    if req.framework:
        try:
            fw = get_framework(req.framework)
        except ValueError:
            raise HTTPException(404, f"Framework not found: {req.framework}")
        result = fw.assess(merged, tenant_id)
        results.append(result.to_dict())
    else:
        for fw_info in list_frameworks():
            fw = get_framework(fw_info["id"])
            result = fw.assess(merged, tenant_id)
            results.append(result.to_dict())

    # Store latest request-scoped report (summary object)
    if len(results) == 1:
        report = results[0]
    else:
        latest = {r["framework_id"]: r for r in results}
        report = {
            "tenant_id": tenant_id,
            "request_id": request_id,
            "frameworks": list(latest.values()),
            "overall_score": round(
                sum(r.get("score_pct", 0) for r in latest.values()) / len(latest) if latest else 0, 1
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    _assessments_by_request.setdefault(tenant_id, {})
    _assessments_by_request[tenant_id][request_id] = report
    return report

@app.get("/assess/{tenant_id}/report")
def get_report(tenant_id: str, framework: Optional[str] = None, dep=Depends(verify_api_key)):
    """Get latest assessment report for a tenant."""
    all_results = _assessments.get(tenant_id, [])
    if not all_results:
        raise HTTPException(404, "No assessments found for tenant")

    if framework:
        filtered = [r for r in all_results if r["framework_id"] == framework]
        if not filtered:
            raise HTTPException(404, f"No assessment found for framework: {framework}")
        return filtered[-1]  # Latest

    # Return summary of latest for each framework
    latest = {}
    for r in all_results:
        latest[r["framework_id"]] = r
    return {
        "tenant_id": tenant_id,
        "frameworks": list(latest.values()),
        "overall_score": round(
            sum(r.get("score_pct", 0) for r in latest.values()) / len(latest) if latest else 0, 1
        ),
    }


@app.get("/assess/{tenant_id}/{request_id}/report")
def get_report_for_request(tenant_id: str, request_id: str, dep=Depends(verify_api_key)):
    """Get the request-scoped assessment report for a specific request_id."""
    report = _assessments_by_request.get(tenant_id, {}).get(request_id)
    if report is None:
        raise HTTPException(404, "No request-scoped assessment found")
    return report

@app.post("/evidence/{tenant_id}")
def submit_evidence(tenant_id: str, submission: EvidenceSubmission, dep=Depends(verify_api_key)):
    """Submit compliance evidence for a tenant. Merges with existing evidence."""
    existing = _evidence.get(tenant_id, {})
    existing.update(submission.evidence)
    _evidence[tenant_id] = existing
    return {
        "tenant_id": tenant_id,
        "evidence_keys": list(existing.keys()),
        "total_keys": len(existing),
    }


@app.post("/evidence/{tenant_id}/{request_id}")
def submit_evidence_for_request(tenant_id: str, request_id: str, submission: EvidenceSubmission, dep=Depends(verify_api_key)):
    """Submit evidence for a specific request_id."""
    tenant_map = _evidence_by_request.setdefault(tenant_id, {})
    existing = tenant_map.get(request_id, {})
    existing.update(submission.evidence)
    tenant_map[request_id] = existing
    return {
        "tenant_id": tenant_id,
        "request_id": request_id,
        "evidence_keys": list(existing.keys()),
        "total_keys": len(existing),
    }

@app.get("/evidence/{tenant_id}")
def get_evidence(tenant_id: str, dep=Depends(verify_api_key)):
    """Get stored compliance evidence for a tenant."""
    evidence = _evidence.get(tenant_id)
    if evidence is None:
        raise HTTPException(404, "No evidence found for tenant")
    return {"tenant_id": tenant_id, "evidence": evidence}


@app.get("/evidence/{tenant_id}/{request_id}")
def get_evidence_for_request(tenant_id: str, request_id: str, dep=Depends(verify_api_key)):
    """Get request-scoped evidence for a specific request_id."""
    evidence = _evidence_by_request.get(tenant_id, {}).get(request_id)
    if evidence is None:
        raise HTTPException(404, "No request-scoped evidence found")
    return {"tenant_id": tenant_id, "request_id": request_id, "evidence": evidence}

@app.delete("/assess/{tenant_id}")
def clear_assessments(tenant_id: str, dep=Depends(verify_api_key)):
    """Clear assessment history for a tenant."""
    _assessments.pop(tenant_id, None)
    return {"status": "cleared", "tenant_id": tenant_id}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8006)
