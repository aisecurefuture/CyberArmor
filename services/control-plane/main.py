import json
import logging
import os
import html as htmlmod
import time
from datetime import datetime, timezone, timedelta
from typing import Annotated, Dict, Optional, Any, List

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db import Base, SessionLocal, engine
from models import ApiKey, AuditLog, Tenant
from uuid import uuid4

import httpx

# In-memory incident store for demo traceability (tenant_id -> request_id -> incident dict)
_INCIDENTS: Dict[str, Dict[str, Dict[str, Any]]] = {}

class ApiKeyOut(BaseModel):
    key: str
    tenant_id: Optional[str]
    role: str
    active: bool

    class Config:
        from_attributes = True

class ApiKeyCreate(BaseModel):
    tenant_id: Optional[str] = None
    role: str = "analyst"

logger = logging.getLogger("control_plane")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

JWT_SECRET = os.getenv("CYBERARMOR_JWT_SECRET", "change-me")
DEFAULT_API_KEY = os.getenv("CYBERARMOR_API_SECRET", "change-me")

# Internal URL for the compliance service (used by the incident viewer page).
COMPLIANCE_URL = os.getenv("COMPLIANCE_URL", "http://compliance:8006")


def init_db():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        if not db.query(ApiKey).filter(ApiKey.key == DEFAULT_API_KEY).first():
            db.add(ApiKey(key=DEFAULT_API_KEY, role="admin", tenant_id=None, active=True))
            db.commit()


def wait_for_db(max_wait_s: int = 45) -> None:
    """Block startup until the DB accepts connections.

    docker-compose often starts app containers before Postgres is actually
    listening (especially during first-time initdb, when Postgres restarts).
    Without a wait loop, the app exits with "connection refused" and the
    reverse proxy returns 502.
    """
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
            # small exponential-ish backoff capped at 2s
            sleep_s = min(0.25 * (1.4 ** (attempt - 1)), 2.0)
            logger.warning("db_not_ready_yet sleep_s=%.2f err=%s", sleep_s, e)
            time.sleep(sleep_s)


class TelemetryEvent(BaseModel):
    tenant_id: str
    user_id: Optional[str] = None
    event_type: str = Field(..., description="e.g., page_visit, form_detected, pii_detected, genai_detected, policy_violation")
    payload: Dict = Field(default_factory=dict)
    source: str = Field(..., description="browser_extension|proxy_agent|endpoint")
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuthContext(BaseModel):
    principal: str
    role: str
    tenant_id: Optional[str]


class TenantOut(BaseModel):
    id: str
    name: str
    active: bool

    class Config:
        from_attributes = True


class AuditLogOut(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    principal: Optional[str] = None
    path: str
    method: str
    status: str
    duration_s: str
    meta: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True


def _coerce_meta(val: Any) -> Optional[Dict[str, Any]]:
    """AuditLog.meta is JSONB in Postgres and Text in SQLite.

    In Postgres it will come back as a dict; in SQLite (or older rows) it may be
    a JSON string.
    """
    if val is None:
        return None
    if isinstance(val, dict):
        return val
    if isinstance(val, (bytes, bytearray)):
        try:
            val = val.decode("utf-8", errors="ignore")
        except Exception:
            return {"raw": str(val)}
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            return parsed if isinstance(parsed, dict) else {"value": parsed}
        except Exception:
            return {"raw": val}
    return {"raw": str(val)}


def _encode_meta_for_db(val: Optional[Dict[str, Any]]) -> Any:
    """Store meta in a backend-safe way.

    AuditLog.meta is JSONB on Postgres but Text on SQLite (via with_variant).
    SQLAlchemy does not auto-serialize dicts into a Text column, so when the
    DB dialect is SQLite we JSON-encode the dict.
    """
    if val is None:
        return None
    try:
        dialect = engine.dialect.name
    except Exception:
        dialect = "unknown"
    if dialect == "sqlite":
        try:
            return json.dumps(val)
        except Exception:
            return json.dumps({"raw": str(val)})
    return val


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_api_key(
    db: Annotated[Session, Depends(get_db)],
    api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None,
) -> Optional[str]:
    if not api_key:
        return None
    record = db.query(ApiKey).filter(ApiKey.key == api_key, ApiKey.active.is_(True)).first()
    if record:
        return record.role
    return None


def verify_bearer_token(authorization: Annotated[Optional[str], Header()] = None) -> Optional[Dict]:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1]
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return claims
    except jwt.PyJWTError:
        return None


def get_auth_context(
    api_key_role: Annotated[Optional[str], Depends(verify_api_key)],
    bearer_identity: Annotated[Optional[Dict], Depends(verify_bearer_token)],
    tenant_id: Annotated[Optional[str], Header(alias="x-tenant-id")] = None,
    role: Annotated[Optional[str], Header(alias="x-role")] = None,
) -> AuthContext:
    identity = bearer_identity or api_key_role
    if not identity:
        raise HTTPException(status_code=401, detail="Unauthorized")
    resolved_role = role or api_key_role or (bearer_identity.get("role") if bearer_identity else None) or "analyst"
    tenant_header = tenant_id or (bearer_identity.get("tenant") if bearer_identity else None)
    return AuthContext(principal="api-key" if api_key_role else "jwt-user", role=resolved_role, tenant_id=tenant_header)


def require_role(required: str):
    def checker(ctx: Annotated[AuthContext, Depends(get_auth_context)]) -> AuthContext:
        if ctx.role not in {required, "admin"}:
            raise HTTPException(status_code=403, detail="Forbidden")
        return ctx

    return checker


app = FastAPI(title="CyberArmor Control Plane", version="0.1.1")

# Allow browser extension and local agents to POST telemetry with preflight.
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


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    start = datetime.now(timezone.utc)
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    principal = request.headers.get("authorization") or request.headers.get("x-api-key", "anonymous")
    tenant = request.headers.get("x-tenant-id", "unknown")
    response = await call_next(request)
    duration = (datetime.now(timezone.utc) - start).total_seconds()
    # Best-effort audit write: never break request handling if the DB is unavailable.
    try:
        with SessionLocal() as db:
            db.add(
                AuditLog(
                    tenant_id=tenant,
                    principal=principal,
                    path=request.url.path,
                    method=request.method,
                    status=str(response.status_code),
                    duration_s=f"{duration:.4f}",
                    meta=_encode_meta_for_db({"client_ip": client_ip}),
                )
            )
            db.commit()
    except Exception as e:
        logger.warning("audit_write_failed err=%s path=%s", e, request.url.path)
    logger.info(
        "audit event=api_call path=%s method=%s status=%s tenant=%s principal=%s duration_s=%.4f client_ip=%s",
        request.url.path,
        request.method,
        response.status_code,
        tenant,
        principal,
        duration,
        client_ip,
    )
    return response


@app.get("/health")
def health():
    return {"status": "ok", "ts": datetime.now(timezone.utc).isoformat()}


@app.get("/tenants", response_model=list[TenantOut])
def list_tenants(ctx: Annotated[AuthContext, Depends(require_role("analyst"))], db: Annotated[Session, Depends(get_db)]):
    if ctx.tenant_id:
        tenant = db.query(Tenant).filter(Tenant.id == ctx.tenant_id).first()
        return [tenant] if tenant else []
    return db.query(Tenant).all()


class TenantCreate(BaseModel):
    id: str
    name: str


@app.post("/tenants", response_model=TenantOut)
def create_tenant(payload: TenantCreate, ctx: Annotated[AuthContext, Depends(require_role("admin"))], db: Annotated[Session, Depends(get_db)]):
    existing = db.query(Tenant).filter(Tenant.id == payload.id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Tenant exists")
    tenant = Tenant(id=payload.id, name=payload.name)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant

@app.get("/apikeys", response_model=list[ApiKeyOut])
def list_apikeys(
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
    db: Annotated[Session, Depends(get_db)]
):
    return db.query(ApiKey).order_by(ApiKey.created_at.desc()).all()

@app.post("/apikeys", response_model=ApiKeyOut)
def create_apikey(
    payload: ApiKeyCreate,
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
    db: Annotated[Session, Depends(get_db)]
):
    new_key = str(uuid4()).replace("-", "")
    record = ApiKey(key=new_key, tenant_id=payload.tenant_id, role=payload.role, active=True)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record

@app.patch("/apikeys/{key}/disable", response_model=ApiKeyOut)
def disable_apikey(
    key: str,
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
    db: Annotated[Session, Depends(get_db)]
    ):
    record = db.query(ApiKey).filter(ApiKey.key == key).first()
    if not record:
        raise HTTPException(status_code=404, detail="Not found")
    record.active = False
    db.commit()
    db.refresh(record)
    return record

@app.post("/telemetry/ingest")
def ingest_event(event: TelemetryEvent, ctx: Annotated[AuthContext, Depends(require_role("analyst"))]):
    if ctx.tenant_id and ctx.tenant_id != event.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant scope mismatch")
    logger.info(
        "telemetry tenant=%s user=%s event_type=%s source=%s",
        event.tenant_id,
        event.user_id,
        event.event_type,
        event.source,
    )
    return JSONResponse({"status": "accepted"}, status_code=202)


class IncidentIngest(BaseModel):
    tenant_id: str
    request_id: str
    event_type: str = "runtime_decision"
    decision: Optional[str] = None
    reasons: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence_snapshot: Optional[Dict[str, Any]] = None
    ts: Optional[float] = None


def _dev_or_key_ok(x_api_key: Optional[str]) -> None:
    """Allow unauth in dev (DEFAULT_API_KEY == change-me); otherwise require key."""
    if not DEFAULT_API_KEY or DEFAULT_API_KEY == "change-me":
        return
    if x_api_key != DEFAULT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.post("/incidents/ingest")
def ingest_incident(payload: IncidentIngest, x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None):
    """Ingest a request-scoped incident.

    This is intentionally lightweight and demo-friendly: it enables exact
    request_id lookups without needing full SIEM storage.
    """
    _dev_or_key_ok(x_api_key)
    tenant_map = _INCIDENTS.setdefault(payload.tenant_id, {})
    incident = payload.model_dump()
    incident.setdefault("received_at", datetime.now(timezone.utc).isoformat())
    tenant_map[payload.request_id] = incident
    return {"status": "stored", "tenant_id": payload.tenant_id, "request_id": payload.request_id}


@app.get("/incidents/{tenant_id}/{request_id}")
def get_incident(tenant_id: str, request_id: str, x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None):
    _dev_or_key_ok(x_api_key)
    inc = _INCIDENTS.get(tenant_id, {}).get(request_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.get("/viewer/{tenant_id}/{request_id}")
def incident_viewer(tenant_id: str, request_id: str, x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None):
    """Sales-friendly incident viewer page.

    This renders a single HTML page that shows:
    - The request-scoped incident stored in control-plane
    - The compliance evidence snapshot for the same request_id
    - The compliance report for the same request_id

    It avoids CORS hassles by fetching evidence/report server-side.
    """
    _dev_or_key_ok(x_api_key)
    inc = _INCIDENTS.get(tenant_id, {}).get(request_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    evidence = None
    report = None
    ev_err = None
    rep_err = None
    try:
        with httpx.Client(timeout=3.0) as client:
            ev = client.get(f"{COMPLIANCE_URL}/evidence/{tenant_id}/{request_id}")
            if ev.status_code == 200:
                evidence = ev.json()
            else:
                ev_err = f"evidence status={ev.status_code}"
            rp = client.get(f"{COMPLIANCE_URL}/assess/{tenant_id}/{request_id}/report")
            if rp.status_code == 200:
                report = rp.json()
            else:
                rep_err = f"report status={rp.status_code}"
    except Exception as exc:
        ev_err = ev_err or f"evidence fetch error: {exc}"
        rep_err = rep_err or f"report fetch error: {exc}"

    def _pre(obj: Any) -> str:
        return htmlmod.escape(json.dumps(obj, indent=2, sort_keys=True))

    incident_json = _pre(inc)
    evidence_json = _pre(evidence) if evidence is not None else htmlmod.escape(ev_err or "No evidence available")
    report_json = _pre(report) if report is not None else htmlmod.escape(rep_err or "No report available")

    html = f"""<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
    <title>Incident Viewer — {tenant_id} / {request_id}</title>
    <style>
      body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 32px; color:#111; }}
      .grid {{ display:grid; grid-template-columns: 1fr; gap: 18px; max-width: 1100px; }}
      .card {{ border: 1px solid #e5e7eb; border-radius: 14px; padding: 18px; box-shadow: 0 2px 14px rgba(0,0,0,0.06); }}
      .muted {{ color:#6b7280; }}
      pre {{ overflow:auto; background:#0b1020; color:#e5e7eb; padding: 14px; border-radius: 12px; font-size: 12px; line-height: 1.4; }}
      code {{ background:#f3f4f6; padding:2px 6px; border-radius: 6px; }}
      a {{ color:#111; }}
      .links a {{ margin-right: 12px; }}
    </style>
  </head>
  <body>
    <h1>Incident Viewer</h1>
    <p class=\"muted\">Tenant: <code>{tenant_id}</code> &nbsp; Request ID: <code>{request_id}</code></p>
    <div class=\"links\">
      <a href=\"/incidents/{tenant_id}/{request_id}\" target=\"_blank\">Incident JSON</a>
      <a href=\"{COMPLIANCE_URL}/evidence/{tenant_id}/{request_id}\" target=\"_blank\">Evidence JSON</a>
      <a href=\"{COMPLIANCE_URL}/assess/{tenant_id}/{request_id}/report\" target=\"_blank\">Compliance report JSON</a>
    </div>
    <div class=\"grid\" style=\"margin-top:18px\">
      <div class=\"card\">
        <h2>Incident</h2>
        <pre>{incident_json}</pre>
      </div>
      <div class=\"card\">
        <h2>Evidence snapshot</h2>
        <pre>{evidence_json}</pre>
      </div>
      <div class=\"card\">
        <h2>Compliance report</h2>
        <pre>{report_json}</pre>
      </div>
    </div>
  </body>
</html>"""
    return HTMLResponse(content=html, status_code=200)


@app.get("/authz/check")
def authz_check(ctx: Annotated[AuthContext, Depends(get_auth_context)]):
    return {"principal": ctx.principal, "role": ctx.role, "tenant": ctx.tenant_id, "exp": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()}


@app.get("/audit", response_model=List[AuditLogOut])
def list_audit_logs(
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 50,
    tenant_id: Optional[str] = None,
    before: Optional[datetime] = None,
):
    """Return recent API-call audit log entries.

    - limit: number of rows (max 500)
    - tenant_id: optional filter (ignored if caller is already tenant-scoped)
    - before: optional cursor (created_at < before)

    The admin dashboard uses this endpoint to populate the Audit Logs table.
    """
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500

    effective_tenant = ctx.tenant_id or tenant_id
    if ctx.tenant_id and tenant_id and tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant scope mismatch")

    q = db.query(AuditLog)
    if effective_tenant:
        q = q.filter(AuditLog.tenant_id == effective_tenant)
    if before:
        q = q.filter(AuditLog.created_at < before)

    rows = q.order_by(AuditLog.created_at.desc()).limit(limit).all()
    # Normalize meta across DB backends.
    for r in rows:
        r.meta = _coerce_meta(r.meta)
    return rows


@app.options("/telemetry/ingest")
def options_ingest():
    return JSONResponse({"status": "ok"}, status_code=200)
