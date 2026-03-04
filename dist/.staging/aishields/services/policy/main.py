"""AIShields Policy Service - Enhanced with AND/OR conditions, enable/disable, action modes.

Fixes from v0.1.1:
- Removed duplicate route definitions
- Fixed Config class placement (now inside Pydantic model)
- Added policy enable/disable, action modes, conditions support
- Added policy sync endpoint for pushing to agents/extensions
- Added compliance framework tagging
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db import Base, SessionLocal, engine
from models import Policy
from policy_engine import EvaluationContext, engine as policy_eval_engine

POLICY_API_SECRET = os.getenv("POLICY_API_SECRET", "change-me-policy")
DEFAULT_PROXY_RUNTIME_MODE = os.getenv("DEFAULT_PROXY_RUNTIME_MODE", "mitm").lower()
_RAW_TENANT_PROXY_MODES = os.getenv("TENANT_PROXY_MODES", "{}")
DEFAULT_TENANT_ID = os.getenv("TENANT_ID", "default")

logger = logging.getLogger("policy_service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def _load_tenant_proxy_modes() -> Dict[str, str]:
    try:
        data = json.loads(_RAW_TENANT_PROXY_MODES)
        if not isinstance(data, dict):
            return {}
        parsed: Dict[str, str] = {}
        for key, value in data.items():
            mode = str(value).strip().lower()
            if mode in {"mitm", "envoy"}:
                parsed[str(key)] = mode
        return parsed
    except Exception:
        logger.warning("invalid TENANT_PROXY_MODES JSON; expected object, got=%s", _RAW_TENANT_PROXY_MODES[:200])
        return {}


TENANT_PROXY_MODE_OVERRIDES = _load_tenant_proxy_modes()


def verify_api_key(api_key: Annotated[str | None, Header(alias="x-api-key")] = None):
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    effective_key = api_key
    if api_key.startswith("PQC:"):
        # PQC-encrypted key support placeholder
        logger.info("PQC-encrypted key received")
    if effective_key != POLICY_API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


def init_db():
    Base.metadata.create_all(bind=engine)


def wait_for_db(max_wait_s: int = 45) -> None:
    start = time.time()
    attempt = 0
    while True:
        attempt += 1
        try:
            with engine.connect() as conn:
                conn.exec_driver_sql("SELECT 1")
            return
        except Exception as e:
            elapsed = time.time() - start
            if elapsed >= max_wait_s:
                logger.error("db_not_ready_after_s=%s last_err=%s", int(elapsed), e)
                raise
            sleep_s = min(0.25 * (1.4 ** (attempt - 1)), 2.0)
            logger.warning("db_not_ready_yet sleep_s=%.2f err=%s", sleep_s, e)
            time.sleep(sleep_s)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Pydantic Models ---

class ConditionRule(BaseModel):
    field: Optional[str] = None
    operator: str = "equals"
    value: Optional[Any] = None
    rules: Optional[List["ConditionRule"]] = None

    class Config:
        from_attributes = True

ConditionRule.model_rebuild()


class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    tenant_id: str
    enabled: bool = True
    action: str = "monitor"  # monitor, block, warn, allow
    priority: int = 100
    conditions: Optional[Dict] = None
    rules: Dict = Field(default_factory=dict)
    compliance_frameworks: Optional[List[str]] = None
    tags: Optional[List[str]] = None


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    action: Optional[str] = None
    priority: Optional[int] = None
    conditions: Optional[Dict] = None
    rules: Optional[Dict] = None
    compliance_frameworks: Optional[List[str]] = None
    tags: Optional[List[str]] = None


class PolicyOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    tenant_id: str
    version: str
    enabled: bool = True
    action: str = "monitor"
    priority: int = 100
    conditions: Optional[Dict] = None
    rules: Dict = Field(default_factory=dict)
    compliance_frameworks: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None

    class Config:
        from_attributes = True


class PolicyToggle(BaseModel):
    enabled: bool


class BulkToggle(BaseModel):
    policy_ids: List[str]
    enabled: bool


class EvaluateRequest(BaseModel):
    tenant_id: str
    context: Dict[str, Any]


class ProxyModeOut(BaseModel):
    tenant_id: str
    mode: str
    source: str


def _coerce_json_field(val: Any) -> Any:
    """Handle JSONB vs Text serialization across DB backends."""
    if val is None:
        return None
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except (json.JSONDecodeError, ValueError):
            return val
    return val


def _encode_json_for_db(val: Any) -> Any:
    """Encode JSON fields for storage based on DB backend."""
    if val is None:
        return None
    try:
        dialect = engine.dialect.name
    except Exception:
        dialect = "unknown"
    if dialect == "sqlite" and isinstance(val, (dict, list)):
        return json.dumps(val)
    return val


def _resolve_tenant_mode(tenant_id: str) -> tuple[str, str]:
    if tenant_id in TENANT_PROXY_MODE_OVERRIDES:
        return TENANT_PROXY_MODE_OVERRIDES[tenant_id], "tenant_override"
    if DEFAULT_PROXY_RUNTIME_MODE in {"mitm", "envoy"}:
        return DEFAULT_PROXY_RUNTIME_MODE, "default"
    return "mitm", "fallback"


def _load_active_policies_for_tenant(db: Session, tenant_id: str) -> List[Dict[str, Any]]:
    rows = (
        db.query(Policy)
        .filter(Policy.tenant_id == tenant_id, Policy.enabled.is_(True))
        .order_by(Policy.priority.asc(), Policy.updated_at.desc())
        .all()
    )
    policies: List[Dict[str, Any]] = []
    for row in rows:
        policies.append(
            {
                "id": row.id,
                "name": row.name,
                "enabled": row.enabled,
                "action": row.action,
                "priority": row.priority,
                "conditions": _coerce_json_field(row.conditions),
                "rules": _coerce_json_field(row.rules) or {},
                "compliance_frameworks": _coerce_json_field(row.compliance_frameworks) or [],
            }
        )
    return policies


# --- Application ---

app = FastAPI(title="AIShields Policy Service", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    wait_for_db()
    init_db()


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.2.0"}


@app.get("/proxy-mode/{tenant_id}", response_model=ProxyModeOut)
def get_proxy_mode(
    tenant_id: str,
    _: Annotated[None, Depends(verify_api_key)],
):
    mode, source = _resolve_tenant_mode(tenant_id)
    return ProxyModeOut(tenant_id=tenant_id, mode=mode, source=source)


@app.get("/policies/{tenant_id}", response_model=List[PolicyOut])
def get_policies_for_tenant(
    tenant_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
    enabled_only: bool = Query(False),
    action: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
):
    """Return all policies for a tenant with optional filters."""
    q = db.query(Policy).filter(Policy.tenant_id == tenant_id)
    if enabled_only:
        q = q.filter(Policy.enabled.is_(True))
    if action:
        q = q.filter(Policy.action == action)
    rows = q.order_by(Policy.priority.asc(), Policy.updated_at.desc()).all()
    if not rows:
        return []
    # Coerce JSON fields
    for r in rows:
        r.conditions = _coerce_json_field(r.conditions)
        r.rules = _coerce_json_field(r.rules) or {}
        r.compliance_frameworks = _coerce_json_field(r.compliance_frameworks)
        r.tags = _coerce_json_field(r.tags)
    return rows


@app.get("/policies/{tenant_id}/{name}", response_model=PolicyOut)
def get_policy(
    tenant_id: str,
    name: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    record = (
        db.query(Policy)
        .filter(Policy.tenant_id == tenant_id, Policy.name == name)
        .order_by(Policy.updated_at.desc())
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Policy not found")
    record.conditions = _coerce_json_field(record.conditions)
    record.rules = _coerce_json_field(record.rules) or {}
    record.compliance_frameworks = _coerce_json_field(record.compliance_frameworks)
    record.tags = _coerce_json_field(record.tags)
    return record


@app.post("/policies", response_model=PolicyOut)
def upsert_policy(
    payload: PolicyCreate,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    record = (
        db.query(Policy)
        .filter(Policy.tenant_id == payload.tenant_id, Policy.name == payload.name)
        .first()
    )
    version = f"v{int(datetime.utcnow().timestamp())}"
    if record:
        record.description = payload.description
        record.rules = _encode_json_for_db(payload.rules)
        record.conditions = _encode_json_for_db(payload.conditions)
        record.enabled = payload.enabled
        record.action = payload.action
        record.priority = payload.priority
        record.compliance_frameworks = _encode_json_for_db(payload.compliance_frameworks)
        record.tags = _encode_json_for_db(payload.tags)
        record.version = version
        record.updated_at = datetime.now(timezone.utc)
    else:
        record = Policy(
            id=str(uuid4()),
            name=payload.name,
            description=payload.description,
            tenant_id=payload.tenant_id,
            version=version,
            enabled=payload.enabled,
            action=payload.action,
            priority=payload.priority,
            conditions=_encode_json_for_db(payload.conditions),
            rules=_encode_json_for_db(payload.rules),
            compliance_frameworks=_encode_json_for_db(payload.compliance_frameworks),
            tags=_encode_json_for_db(payload.tags),
        )
        db.add(record)
    db.commit()
    db.refresh(record)
    record.conditions = _coerce_json_field(record.conditions)
    record.rules = _coerce_json_field(record.rules) or {}
    record.compliance_frameworks = _coerce_json_field(record.compliance_frameworks)
    record.tags = _coerce_json_field(record.tags)
    logger.info("policy upserted tenant=%s name=%s version=%s action=%s", payload.tenant_id, payload.name, version, payload.action)
    return record


@app.put("/policies/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: str,
    payload: PolicyUpdate,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    record = db.query(Policy).filter(Policy.id == policy_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Policy not found")
    if payload.name is not None:
        record.name = payload.name
    if payload.description is not None:
        record.description = payload.description
    if payload.enabled is not None:
        record.enabled = payload.enabled
    if payload.action is not None:
        record.action = payload.action
    if payload.priority is not None:
        record.priority = payload.priority
    if payload.conditions is not None:
        record.conditions = _encode_json_for_db(payload.conditions)
    if payload.rules is not None:
        record.rules = _encode_json_for_db(payload.rules)
    if payload.compliance_frameworks is not None:
        record.compliance_frameworks = _encode_json_for_db(payload.compliance_frameworks)
    if payload.tags is not None:
        record.tags = _encode_json_for_db(payload.tags)
    record.version = f"v{int(datetime.utcnow().timestamp())}"
    record.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(record)
    record.conditions = _coerce_json_field(record.conditions)
    record.rules = _coerce_json_field(record.rules) or {}
    record.compliance_frameworks = _coerce_json_field(record.compliance_frameworks)
    record.tags = _coerce_json_field(record.tags)
    logger.info("policy updated id=%s name=%s", policy_id, record.name)
    return record


@app.patch("/policies/{policy_id}/toggle", response_model=PolicyOut)
def toggle_policy(
    policy_id: str,
    body: PolicyToggle,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    record = db.query(Policy).filter(Policy.id == policy_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Policy not found")
    record.enabled = body.enabled
    record.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(record)
    record.conditions = _coerce_json_field(record.conditions)
    record.rules = _coerce_json_field(record.rules) or {}
    logger.info("policy toggled id=%s enabled=%s", policy_id, body.enabled)
    return record


@app.post("/policies/bulk-toggle")
def bulk_toggle_policies(
    body: BulkToggle,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    count = (
        db.query(Policy)
        .filter(Policy.id.in_(body.policy_ids))
        .update({Policy.enabled: body.enabled, Policy.updated_at: datetime.now(timezone.utc)}, synchronize_session="fetch")
    )
    db.commit()
    return {"status": "ok", "updated": count}


@app.delete("/policies/{policy_id}")
def delete_policy(
    policy_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    record = db.query(Policy).filter(Policy.id == policy_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(record)
    db.commit()
    logger.info("policy deleted id=%s name=%s", policy_id, record.name)
    return {"status": "deleted", "id": policy_id}


@app.get("/policies/{tenant_id}/export")
def export_policies(
    tenant_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    """Export all policies for a tenant (for sync to agents/extensions)."""
    rows = db.query(Policy).filter(Policy.tenant_id == tenant_id).order_by(Policy.priority.asc()).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "enabled": r.enabled,
            "action": r.action,
            "priority": r.priority,
            "conditions": _coerce_json_field(r.conditions),
            "rules": _coerce_json_field(r.rules) or {},
            "compliance_frameworks": _coerce_json_field(r.compliance_frameworks),
            "tags": _coerce_json_field(r.tags),
            "version": r.version,
        }
        for r in rows
    ]


@app.post("/evaluate")
def evaluate_policy(
    body: EvaluateRequest,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    policies = _load_active_policies_for_tenant(db, body.tenant_id)
    if not policies:
        return {"action": "allow", "reason": "no_active_policies"}

    context = EvaluationContext(
        request=body.context.get("request", {}),
        content=body.context.get("content", {}),
        user=body.context.get("user", {}),
        endpoint=body.context.get("endpoint", {}),
        metadata=body.context.get("metadata", {}),
    )
    match = policy_eval_engine.evaluate_first_match(policies, context)
    if not match:
        return {"action": "allow", "reason": "no_policy_match"}

    return {
        "action": match.action,
        "reason": match.reason,
        "policy_id": match.policy_id,
        "policy_name": match.policy_name,
        "matched_rules": match.matched_rules,
        "compliance_frameworks": match.compliance_frameworks,
    }


@app.api_route("/ext_authz/check", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def ext_authz_check(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    from fastapi import Response

    tenant_id = request.headers.get("x-tenant-id", DEFAULT_TENANT_ID)
    mode, _ = _resolve_tenant_mode(tenant_id)
    response = Response(status_code=200)
    response.headers["x-aishields-run-mode"] = mode
    response.headers["x-aishields-tenant-id"] = tenant_id

    # If tenant is configured for mitm mode, Envoy authz should pass through.
    if mode == "mitm":
        response.headers["x-aishields-authz"] = "bypass_mitm_mode"
        return response

    request_path = request.headers.get("x-envoy-original-path", request.url.path)
    request_method = request.headers.get("x-envoy-original-method", request.method)
    request_host = request.headers.get("x-forwarded-host", request.headers.get("host", ""))
    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="replace")[:2048] if body_bytes else ""

    context = EvaluationContext(
        request={
            "url": request_path,
            "method": request_method,
            "host": request_host,
            "headers": dict(request.headers),
            "body_snippet": body_text,
        },
        user={"client_ip": request.headers.get("x-forwarded-for", "")},
    )
    policies = _load_active_policies_for_tenant(db, tenant_id)
    match = policy_eval_engine.evaluate_first_match(policies, context) if policies else None
    if not match:
        response.headers["x-aishields-authz"] = "allow_no_match"
        return response

    response.headers["x-aishields-policy-id"] = match.policy_id
    response.headers["x-aishields-policy-name"] = match.policy_name
    response.headers["x-aishields-policy-action"] = match.action

    if match.action == "block":
        raise HTTPException(status_code=403, detail=f"Blocked by policy: {match.policy_name}")
    if match.action == "warn":
        response.headers["x-aishields-warning"] = match.reason or "policy_warn"
    return response
