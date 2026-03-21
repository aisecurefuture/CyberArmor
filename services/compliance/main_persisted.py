"""CyberArmor Compliance Framework Engine — PostgreSQL-backed persistence."""

from __future__ import annotations

import os
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, DateTime, JSON, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

from frameworks import list_frameworks, get_framework

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("compliance")

API_SECRET = os.getenv("COMPLIANCE_API_SECRET", "change-me-compliance")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://cyberarmor:cyberarmor@postgres:5432/cyberarmor")
SERVICE_STARTED_AT = datetime.now(timezone.utc)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class ComplianceEvidenceModel(Base):
    __tablename__ = "compliance_evidence"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    request_id = Column(String(64), nullable=True, index=True)
    evidence = Column(JSON, nullable=False, default=dict)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class ComplianceAssessmentModel(Base):
    __tablename__ = "compliance_assessments"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    request_id = Column(String(64), nullable=True, index=True)
    framework_id = Column(String(64), nullable=False, index=True)
    report = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)


app = FastAPI(title="CyberArmor Compliance Engine", version="1.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)


def verify_api_key(x_api_key: str = Header(None)):
    if not API_SECRET or API_SECRET == "change-me-compliance":
        return
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="Invalid API key")


class AssessmentRequest(BaseModel):
    framework: Optional[str] = None
    evidence: Optional[Dict] = None


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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _fetch_evidence(db: Session, tenant_id: str, request_id: Optional[str]) -> Dict:
    rec = (
        db.query(ComplianceEvidenceModel)
        .filter(
            ComplianceEvidenceModel.tenant_id == tenant_id,
            ComplianceEvidenceModel.request_id == request_id,
        )
        .order_by(ComplianceEvidenceModel.updated_at.desc(), ComplianceEvidenceModel.id.desc())
        .first()
    )
    return dict(rec.evidence or {}) if rec else {}


def _upsert_evidence(db: Session, tenant_id: str, request_id: Optional[str], new_values: Dict) -> Dict:
    rec = (
        db.query(ComplianceEvidenceModel)
        .filter(
            ComplianceEvidenceModel.tenant_id == tenant_id,
            ComplianceEvidenceModel.request_id == request_id,
        )
        .order_by(ComplianceEvidenceModel.updated_at.desc(), ComplianceEvidenceModel.id.desc())
        .first()
    )
    merged = dict(rec.evidence or {}) if rec else {}
    merged.update(new_values or {})
    now = datetime.now(timezone.utc)
    if rec:
        rec.evidence = merged
        rec.updated_at = now
    else:
        db.add(
            ComplianceEvidenceModel(
                tenant_id=tenant_id,
                request_id=request_id,
                evidence=merged,
                updated_at=now,
            )
        )
    db.commit()
    return merged


def _store_assessment_rows(db: Session, tenant_id: str, request_id: Optional[str], results: List[Dict]) -> None:
    now = datetime.now(timezone.utc)
    for r in results:
        db.add(
            ComplianceAssessmentModel(
                tenant_id=tenant_id,
                request_id=request_id,
                framework_id=str(r.get("framework_id", "unknown")),
                report=r,
                created_at=now,
            )
        )
    db.commit()


@app.get("/health")
def health():
    return {"status": "ok", "service": "compliance", "frameworks": len(list_frameworks())}


@app.get("/ready")
def ready():
    return {
        "status": "ready",
        "service": "compliance",
        "frameworks": len(list_frameworks()),
        "version": "1.1.0",
    }


@app.get("/metrics")
def metrics_endpoint(db: Session = Depends(get_db)):
    uptime = round((datetime.now(timezone.utc) - SERVICE_STARTED_AT).total_seconds(), 3)
    tenants_with_assessments = db.query(ComplianceAssessmentModel.tenant_id).distinct().count()
    tenants_with_evidence = db.query(ComplianceEvidenceModel.tenant_id).distinct().count()
    return PlainTextResponse(
        "\n".join([
            "# HELP cyberarmor_compliance_uptime_seconds Service uptime in seconds",
            "# TYPE cyberarmor_compliance_uptime_seconds gauge",
            f"cyberarmor_compliance_uptime_seconds{{service=\"compliance\",version=\"1.1.0\"}} {uptime}",
            "# HELP cyberarmor_compliance_tenants_with_assessments Tenants with at least one assessment",
            "# TYPE cyberarmor_compliance_tenants_with_assessments gauge",
            f"cyberarmor_compliance_tenants_with_assessments{{service=\"compliance\"}} {tenants_with_assessments}",
            "# HELP cyberarmor_compliance_tenants_with_evidence Tenants with any evidence records",
            "# TYPE cyberarmor_compliance_tenants_with_evidence gauge",
            f"cyberarmor_compliance_tenants_with_evidence{{service=\"compliance\"}} {tenants_with_evidence}",
        ]) + "\n",
        media_type="text/plain",
    )


@app.get("/frameworks", response_model=List[FrameworkInfo])
def get_frameworks(dep=Depends(verify_api_key)):
    return list_frameworks()


@app.get("/frameworks/{framework_id}/controls", response_model=List[ControlInfo])
def get_framework_controls(framework_id: str, dep=Depends(verify_api_key)):
    try:
        fw = get_framework(framework_id)
    except ValueError:
        raise HTTPException(404, f"Framework not found: {framework_id}")
    controls = fw.get_controls()
    return [
        ControlInfo(
            id=c.id,
            name=c.name,
            description=c.description,
            category=c.category,
            severity=c.severity,
            automated=c.automated,
        )
        for c in controls
    ]


@app.post("/assess/{tenant_id}")
def run_assessment(tenant_id: str, req: AssessmentRequest, db: Session = Depends(get_db), dep=Depends(verify_api_key)):
    stored = _fetch_evidence(db, tenant_id, request_id=None)
    merged = {**stored, **(req.evidence or {})}
    results = []
    if req.framework:
        try:
            fw = get_framework(req.framework)
        except ValueError:
            raise HTTPException(404, f"Framework not found: {req.framework}")
        results.append(fw.assess(merged, tenant_id).to_dict())
    else:
        for fw_info in list_frameworks():
            fw = get_framework(fw_info["id"])
            results.append(fw.assess(merged, tenant_id).to_dict())
    _store_assessment_rows(db, tenant_id=tenant_id, request_id=None, results=results)
    if len(results) == 1:
        return results[0]
    return {
        "tenant_id": tenant_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "frameworks_assessed": len(results),
        "results": results,
    }


@app.post("/assess/{tenant_id}/{request_id}")
def run_assessment_for_request(
    tenant_id: str, request_id: str, req: AssessmentRequest, db: Session = Depends(get_db), dep=Depends(verify_api_key)
):
    stored = _fetch_evidence(db, tenant_id, request_id=request_id)
    merged = {**stored, **(req.evidence or {})}
    results = []
    if req.framework:
        try:
            fw = get_framework(req.framework)
        except ValueError:
            raise HTTPException(404, f"Framework not found: {req.framework}")
        results.append(fw.assess(merged, tenant_id).to_dict())
    else:
        for fw_info in list_frameworks():
            fw = get_framework(fw_info["id"])
            results.append(fw.assess(merged, tenant_id).to_dict())
    _store_assessment_rows(db, tenant_id=tenant_id, request_id=request_id, results=results)
    if len(results) == 1:
        return results[0]
    latest = {r["framework_id"]: r for r in results}
    return {
        "tenant_id": tenant_id,
        "request_id": request_id,
        "frameworks": list(latest.values()),
        "overall_score": round(sum(r.get("score_pct", 0) for r in latest.values()) / len(latest) if latest else 0, 1),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/assess/{tenant_id}/report")
def get_report(
    tenant_id: str, framework: Optional[str] = None, db: Session = Depends(get_db), dep=Depends(verify_api_key)
):
    q = db.query(ComplianceAssessmentModel).filter(
        ComplianceAssessmentModel.tenant_id == tenant_id,
        ComplianceAssessmentModel.request_id.is_(None),
    )
    if framework:
        q = q.filter(ComplianceAssessmentModel.framework_id == framework)
    rows = q.order_by(ComplianceAssessmentModel.created_at.asc(), ComplianceAssessmentModel.id.asc()).all()
    if not rows:
        raise HTTPException(404, "No assessments found for tenant")
    if framework:
        return rows[-1].report
    latest: Dict[str, Dict] = {}
    for row in rows:
        latest[row.framework_id] = row.report
    return {
        "tenant_id": tenant_id,
        "frameworks": list(latest.values()),
        "overall_score": round(sum(r.get("score_pct", 0) for r in latest.values()) / len(latest) if latest else 0, 1),
    }


@app.get("/assess/{tenant_id}/{request_id}/report")
def get_report_for_request(tenant_id: str, request_id: str, db: Session = Depends(get_db), dep=Depends(verify_api_key)):
    rows = (
        db.query(ComplianceAssessmentModel)
        .filter(
            ComplianceAssessmentModel.tenant_id == tenant_id,
            ComplianceAssessmentModel.request_id == request_id,
        )
        .order_by(ComplianceAssessmentModel.created_at.asc(), ComplianceAssessmentModel.id.asc())
        .all()
    )
    if not rows:
        raise HTTPException(404, "No request-scoped assessment found")
    latest: Dict[str, Dict] = {}
    for row in rows:
        latest[row.framework_id] = row.report
    if len(latest) == 1:
        return list(latest.values())[0]
    return {
        "tenant_id": tenant_id,
        "request_id": request_id,
        "frameworks": list(latest.values()),
        "overall_score": round(sum(r.get("score_pct", 0) for r in latest.values()) / len(latest) if latest else 0, 1),
    }


@app.post("/evidence/{tenant_id}")
def submit_evidence(
    tenant_id: str, submission: EvidenceSubmission, db: Session = Depends(get_db), dep=Depends(verify_api_key)
):
    merged = _upsert_evidence(db, tenant_id=tenant_id, request_id=None, new_values=submission.evidence)
    return {"tenant_id": tenant_id, "evidence_keys": list(merged.keys()), "total_keys": len(merged)}


@app.post("/evidence/{tenant_id}/{request_id}")
def submit_evidence_for_request(
    tenant_id: str, request_id: str, submission: EvidenceSubmission, db: Session = Depends(get_db), dep=Depends(verify_api_key)
):
    merged = _upsert_evidence(db, tenant_id=tenant_id, request_id=request_id, new_values=submission.evidence)
    return {
        "tenant_id": tenant_id,
        "request_id": request_id,
        "evidence_keys": list(merged.keys()),
        "total_keys": len(merged),
    }


@app.get("/evidence/{tenant_id}")
def get_evidence(tenant_id: str, db: Session = Depends(get_db), dep=Depends(verify_api_key)):
    evidence = _fetch_evidence(db, tenant_id=tenant_id, request_id=None)
    if not evidence:
        raise HTTPException(404, "No evidence found for tenant")
    return {"tenant_id": tenant_id, "evidence": evidence}


@app.get("/evidence/{tenant_id}/{request_id}")
def get_evidence_for_request(
    tenant_id: str, request_id: str, db: Session = Depends(get_db), dep=Depends(verify_api_key)
):
    evidence = _fetch_evidence(db, tenant_id=tenant_id, request_id=request_id)
    if not evidence:
        raise HTTPException(404, "No request-scoped evidence found")
    return {"tenant_id": tenant_id, "request_id": request_id, "evidence": evidence}


@app.delete("/assess/{tenant_id}")
def clear_assessments(tenant_id: str, db: Session = Depends(get_db), dep=Depends(verify_api_key)):
    db.query(ComplianceAssessmentModel).filter(ComplianceAssessmentModel.tenant_id == tenant_id).delete()
    db.commit()
    return {"status": "cleared", "tenant_id": tenant_id}

