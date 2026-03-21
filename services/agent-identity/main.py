"""CyberArmor Agent Identity Service.

Manages AI agent identities, credentials, tokens, and delegation chains.
This is a new service alongside the existing human Identity Service (port 8004).
Port: 8008
"""

import logging
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Annotated, Any, Dict, List, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict, model_validator
from sqlalchemy import Column, String, Integer, DateTime, JSON, create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("agent_identity_service")

AGENT_IDENTITY_API_SECRET = os.getenv("AGENT_IDENTITY_API_SECRET", "change-me-agent-identity")
AGENT_IDENTITY_JWT_SECRET = os.getenv("AGENT_IDENTITY_JWT_SECRET", "change-me-jwt-secret")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://cyberarmor:cyberarmor@postgres:5432/cyberarmor")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
ENFORCE_SECURE_SECRETS = os.getenv("CYBERARMOR_ENFORCE_SECURE_SECRETS", "false").strip().lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_DEFAULTS = os.getenv("CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "false").strip().lower() in {"1", "true", "yes", "on"}
ENFORCE_MTLS = os.getenv("CYBERARMOR_ENFORCE_MTLS", "false").strip().lower() in {"1", "true", "yes", "on"}
TLS_CA_FILE = os.getenv("CYBERARMOR_TLS_CA_FILE")
TLS_CERT_FILE = os.getenv("CYBERARMOR_TLS_CERT_FILE")
TLS_KEY_FILE = os.getenv("CYBERARMOR_TLS_KEY_FILE")


def _enforce_secure_secrets() -> None:
    if not ENFORCE_SECURE_SECRETS or ALLOW_INSECURE_DEFAULTS:
        return

    def _bad(value: Optional[str]) -> bool:
        if not value:
            return True
        lowered = value.strip().lower()
        return lowered.startswith("change-me") or "changeme" in lowered

    failing = []
    if _bad(AGENT_IDENTITY_API_SECRET):
        failing.append("AGENT_IDENTITY_API_SECRET")
    if _bad(AGENT_IDENTITY_JWT_SECRET):
        failing.append("AGENT_IDENTITY_JWT_SECRET")
    if failing:
        raise RuntimeError(
            "Refusing startup with insecure defaults in strict secret mode. "
            f"Set strong values for: {', '.join(failing)}. "
            "For local dev only, set CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true."
        )


_enforce_secure_secrets()


def _enforce_mtls_config() -> None:
    if not ENFORCE_MTLS:
        return
    missing = []
    for env_name, value in [
        ("CYBERARMOR_TLS_CA_FILE", TLS_CA_FILE),
        ("CYBERARMOR_TLS_CERT_FILE", TLS_CERT_FILE),
        ("CYBERARMOR_TLS_KEY_FILE", TLS_KEY_FILE),
    ]:
        if not value:
            missing.append(f"{env_name}(unset)")
        elif not os.path.exists(value):
            missing.append(f"{env_name}({value} missing)")
    if missing:
        raise RuntimeError(
            "Refusing startup: mTLS enforced but TLS artifacts are missing. "
            f"Fix: {', '.join(missing)}"
        )


_enforce_mtls_config()

# ── Database ──────────────────────────────────────────────────────────────────

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class AgentModel(Base):
    __tablename__ = "agents"
    agent_id = Column(String(64), primary_key=True)
    display_name = Column(String(255), nullable=False)
    agent_type = Column(String(64), nullable=False, default="autonomous")
    owner_team = Column(String(255), nullable=False)
    owner_human_id = Column(String(255), nullable=True)
    application = Column(String(255), nullable=False)
    environment = Column(String(64), nullable=False, default="production")
    ai_provider = Column(String(64), nullable=False)
    model = Column(String(255), nullable=False)
    framework = Column(String(64), nullable=False, default="custom")
    allowed_tools = Column(JSON, default=list)
    denied_tools = Column(JSON, default=list)
    sensitivity_tier = Column(String(64), nullable=False, default="internal")
    credential_type = Column(String(64), nullable=False, default="jwt")
    credential_ttl_seconds = Column(Integer, default=3600)
    tags = Column(JSON, default=dict)
    status = Column(String(64), default="active")
    tenant_id = Column(String(64), nullable=False, default="default")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class DelegationModel(Base):
    __tablename__ = "agent_delegations"
    chain_id = Column(String(64), primary_key=True)
    parent_human_id = Column(String(255), nullable=False)
    agent_id = Column(String(64), nullable=False)
    scope = Column(JSON, default=list)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(32), default="active")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class RevocationModel(Base):
    __tablename__ = "agent_token_revocations"
    token_id = Column(String(64), primary_key=True)
    agent_id = Column(String(64), nullable=False)
    revoked_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _new_agent_id() -> str:
    return "agt_" + str(uuid4()).replace("-", "")[:20]

def _new_chain_id() -> str:
    return "del_" + str(uuid4()).replace("-", "")[:20]

def _new_token_id() -> str:
    return "tok_" + str(uuid4()).replace("-", "")[:20]


def _issue_jwt(agent: AgentModel, jti: str) -> str:
    try:
        from jose import jwt as _jwt
        payload = {
            "sub": agent.agent_id,
            "jti": jti,
            "agent_id": agent.agent_id,
            "tenant_id": agent.tenant_id,
            "owner_human_id": agent.owner_human_id,
            "allowed_tools": agent.allowed_tools or [],
            "sensitivity_tier": agent.sensitivity_tier,
            "environment": agent.environment,
            "iat": int(time.time()),
            "exp": int(time.time()) + agent.credential_ttl_seconds,
        }
        return _jwt.encode(payload, AGENT_IDENTITY_JWT_SECRET, algorithm="HS256")
    except Exception as e:
        logger.warning("JWT issue failed (jose not installed?): %s", e)
        return f"fallback-{jti}"


def _verify_jwt(token: str) -> Dict:
    try:
        from jose import jwt as _jwt
        return _jwt.decode(token, AGENT_IDENTITY_JWT_SECRET, algorithms=["HS256"])
    except Exception as e:
        raise ValueError(f"Invalid token: {e}")


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
                logger.error("DB not ready after %ds: %s", int(elapsed), e)
                raise
            sleep_s = min(0.25 * (1.4 ** (attempt - 1)), 2.0)
            logger.warning("DB not ready, retrying in %.2fs: %s", sleep_s, e)
            time.sleep(sleep_s)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_api_key(api_key: Annotated[str | None, Header(alias="x-api-key")] = None):
    if not api_key or api_key != AGENT_IDENTITY_API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


# ── Pydantic Models ───────────────────────────────────────────────────────────

class AgentCreate(BaseModel):
    display_name: Optional[str] = None
    agent_type: str = "autonomous"
    owner_team: Optional[str] = None
    owner_human_id: Optional[str] = None
    application: Optional[str] = None
    environment: str = "production"
    ai_provider: str = "openai"
    model: str = "gpt-4o"
    framework: str = "custom"
    allowed_tools: List[str] = Field(default_factory=list)
    denied_tools: List[str] = Field(default_factory=list)
    sensitivity_tier: str = "internal"
    credential_type: str = "jwt"
    credential_ttl_seconds: int = 3600
    tags: Dict[str, Any] = Field(default_factory=dict)
    tenant_id: str = "default"
    # Backward-compatible dashboard fields
    name: Optional[str] = None
    description: Optional[str] = None
    trust_level: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)
    max_requests_per_minute: Optional[int] = None

    model_config = ConfigDict(extra="ignore")

    @model_validator(mode="after")
    def ensure_minimum_required(self):
        if not self.display_name and self.name:
            self.display_name = self.name
        if not self.owner_team:
            self.owner_team = "unassigned"
        if not self.application:
            self.application = self.display_name or self.name or "legacy-agent"
        if not self.allowed_tools and self.capabilities:
            self.allowed_tools = list(self.capabilities)
        if not self.display_name:
            raise ValueError("display_name or name is required")
        return self


class AgentOut(BaseModel):
    agent_id: str
    display_name: str
    agent_type: str
    owner_team: str
    owner_human_id: Optional[str]
    application: str
    environment: str
    ai_provider: str
    model: str
    framework: str
    allowed_tools: List[str]
    denied_tools: List[str]
    sensitivity_tier: str
    credential_type: str
    credential_ttl_seconds: int
    tags: Dict[str, Any]
    status: str
    tenant_id: str
    created_at: Optional[datetime]
    last_seen_at: Optional[datetime]
    # Legacy aliases expected by the current admin dashboard
    name: Optional[str] = None
    trust_level: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class TokenResponse(BaseModel):
    token: str
    access_token: str
    token_id: str
    expires_at: datetime
    agent_id: str
    ttl_seconds: int
    expires_in: int
    scopes: List[str] = Field(default_factory=lambda: ["ai:inference", "ai:audit"])


class DelegationCreate(BaseModel):
    parent_human_id: str
    agent_id: str
    scope: List[str] = ["*"]
    expires_at: Optional[datetime] = None


class DelegationOut(BaseModel):
    chain_id: str
    parent_human_id: str
    agent_id: str
    scope: List[str]
    expires_at: Optional[datetime]
    status: str
    created_at: datetime


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="CyberArmor Agent Identity Service",
    version="1.0.0",
    description="AI Agent Identity, Credential Issuance, and Delegation Management",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    logger.info("Agent Identity Service starting up...")
    wait_for_db()
    Base.metadata.create_all(bind=engine)
    logger.info("Agent Identity Service ready on port 8008")


# ── Agent Endpoints ───────────────────────────────────────────────────────────

@app.post("/agents/register", response_model=AgentOut, status_code=201)
def register_agent(
    body: AgentCreate,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Register a new AI agent identity."""
    agent_id = _new_agent_id()
    tags = dict(body.tags or {})
    if body.trust_level and "trust_level" not in tags:
        tags["trust_level"] = body.trust_level
    if body.description and "description" not in tags:
        tags["description"] = body.description
    if body.max_requests_per_minute is not None and "max_requests_per_minute" not in tags:
        tags["max_requests_per_minute"] = body.max_requests_per_minute

    agent = AgentModel(
        agent_id=agent_id,
        display_name=body.display_name or body.name or "unnamed-agent",
        agent_type=body.agent_type,
        owner_team=body.owner_team or "unassigned",
        owner_human_id=body.owner_human_id,
        application=body.application or (body.display_name or body.name or "legacy-agent"),
        environment=body.environment,
        ai_provider=body.ai_provider,
        model=body.model,
        framework=body.framework,
        allowed_tools=body.allowed_tools or body.capabilities,
        denied_tools=body.denied_tools,
        sensitivity_tier=body.sensitivity_tier,
        credential_type=body.credential_type,
        credential_ttl_seconds=body.credential_ttl_seconds,
        tags=tags,
        tenant_id=body.tenant_id,
        status="active",
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    logger.info("Agent registered: agent_id=%s tenant=%s", agent_id, body.tenant_id)
    return _agent_to_out(agent)


@app.get("/agents", response_model=List[AgentOut])
def list_agents(
    tenant_id: Optional[str] = None,
    status: Optional[str] = None,
    environment: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """List agents scoped by tenant."""
    q = db.query(AgentModel)
    if tenant_id:
        q = q.filter(AgentModel.tenant_id == tenant_id)
    if status:
        q = q.filter(AgentModel.status == status)
    if environment:
        q = q.filter(AgentModel.environment == environment)
    agents = q.offset(offset).limit(limit).all()
    return [_agent_to_out(a) for a in agents]


@app.get("/agents/{agent_id}", response_model=AgentOut)
def get_agent(agent_id: str, db: Session = Depends(get_db), _: None = Depends(verify_api_key)):
    agent = _get_agent_or_404(db, agent_id)
    return _agent_to_out(agent)


@app.put("/agents/{agent_id}", response_model=AgentOut)
def update_agent(
    agent_id: str,
    body: AgentCreate,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    agent = _get_agent_or_404(db, agent_id)
    payload = body.model_dump(exclude_unset=True)
    tags = dict(agent.tags or {})

    # Backward-compatible alias: dashboard sends legacy fields.
    if "name" in payload and "display_name" not in payload:
        payload["display_name"] = payload.get("name")
    if "display_name" in payload:
        agent.display_name = payload["display_name"]
    if "capabilities" in payload and "allowed_tools" not in payload:
        payload["allowed_tools"] = list(payload["capabilities"])

    allowed_fields = {
        "agent_type", "owner_team", "owner_human_id", "application", "environment",
        "ai_provider", "model", "framework", "allowed_tools", "denied_tools",
        "sensitivity_tier", "credential_type", "credential_ttl_seconds", "tenant_id",
        "status",
    }
    for field_name in allowed_fields:
        if field_name in payload:
            setattr(agent, field_name, payload[field_name])

    if "description" in payload:
        if payload["description"] is not None:
            tags["description"] = payload["description"]
        elif "description" in tags:
            tags.pop("description", None)
    if "trust_level" in payload and payload["trust_level"] is not None:
        tags["trust_level"] = payload["trust_level"]
    if "max_requests_per_minute" in payload:
        if payload["max_requests_per_minute"] is not None:
            tags["max_requests_per_minute"] = payload["max_requests_per_minute"]
        elif "max_requests_per_minute" in tags:
            tags.pop("max_requests_per_minute", None)
    if "tags" in payload and payload["tags"] is not None:
        tags.update(payload["tags"])
    agent.tags = tags

    agent.last_seen_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(agent)
    return _agent_to_out(agent)


@app.delete("/agents/{agent_id}")
def decommission_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    agent = _get_agent_or_404(db, agent_id)
    agent.status = "decommissioned"
    db.commit()
    logger.info("Agent decommissioned: agent_id=%s", agent_id)
    return {"agent_id": agent_id, "status": "decommissioned"}


@app.post("/agents/{agent_id}/rotate")
def rotate_agent_credentials(
    agent_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    agent = _get_agent_or_404(db, agent_id)
    jti = _new_token_id()
    token = _issue_jwt(agent, jti)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=agent.credential_ttl_seconds)
    logger.info("Credentials rotated: agent_id=%s jti=%s", agent_id, jti)
    return TokenResponse(
        token=token,
        access_token=token,
        token_id=jti,
        expires_at=expires_at,
        agent_id=agent_id,
        ttl_seconds=agent.credential_ttl_seconds,
        expires_in=agent.credential_ttl_seconds,
    )


@app.get("/agents/{agent_id}/lineage")
def get_agent_lineage(
    agent_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    agent = _get_agent_or_404(db, agent_id)
    delegations = db.query(DelegationModel).filter(
        DelegationModel.agent_id == agent_id,
        DelegationModel.status == "active",
    ).all()
    chain = [
        {
            "chain_id": d.chain_id,
            "parent_human_id": d.parent_human_id,
            "scope": d.scope,
            "expires_at": d.expires_at.isoformat() if d.expires_at else None,
        }
        for d in delegations
    ]
    return {"agent_id": agent_id, "display_name": agent.display_name, "chain": chain}


# ── Token Endpoints ───────────────────────────────────────────────────────────

@app.post("/agents/{agent_id}/tokens/issue", response_model=TokenResponse)
def issue_token(
    agent_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    agent = _get_agent_or_404(db, agent_id)
    if agent.status != "active":
        raise HTTPException(status_code=403, detail=f"Agent is {agent.status}")
    jti = _new_token_id()
    token = _issue_jwt(agent, jti)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=agent.credential_ttl_seconds)
    agent.last_seen_at = datetime.now(timezone.utc)
    db.commit()
    return TokenResponse(
        token=token,
        access_token=token,
        token_id=jti,
        expires_at=expires_at,
        agent_id=agent_id,
        ttl_seconds=agent.credential_ttl_seconds,
        expires_in=agent.credential_ttl_seconds,
    )


@app.post("/agents/{agent_id}/tokens/validate")
def validate_token(
    agent_id: str,
    body: Dict[str, str],
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    token = body.get("token", "") or body.get("access_token", "")
    try:
        claims = _verify_jwt(token)
        jti = claims.get("jti", "")
        # Check revocation list
        revoked = db.query(RevocationModel).filter(RevocationModel.token_id == jti).first()
        if revoked:
            return {"valid": False, "claims": {}, "reason": "TOKEN_REVOKED"}
        if claims.get("agent_id") != agent_id:
            return {"valid": False, "claims": {}, "reason": "AGENT_MISMATCH"}
        return {"valid": True, "claims": claims, "reason": "VALID"}
    except ValueError as e:
        return {"valid": False, "claims": {}, "reason": str(e)}


@app.post("/agents/{agent_id}/tokens/revoke")
def revoke_token(
    agent_id: str,
    body: Dict[str, str],
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    token_id = body.get("token_id", "")
    if not token_id:
        raise HTTPException(status_code=400, detail="token_id required")
    revocation = RevocationModel(token_id=token_id, agent_id=agent_id)
    db.merge(revocation)
    db.commit()
    return {"status": "revoked", "token_id": token_id}


# ── Workload Endpoints ────────────────────────────────────────────────────────

@app.post("/workloads/attest")
def attest_workload(body: Dict[str, Any], _: None = Depends(verify_api_key)):
    """SPIFFE-compatible workload identity attestation."""
    workload_id = "wl_" + str(uuid4()).replace("-", "")[:20]
    agent_id = body.get("agent_id", "unknown")
    namespace = body.get("namespace", "default")
    service_account = body.get("service_account", "default")
    svid = f"spiffe://cyberarmor.ai/{namespace}/{service_account}/{agent_id}"
    return {
        "workload_id": workload_id,
        "svid": svid,
        "agent_id": agent_id,
        "namespace": namespace,
        "service_account": service_account,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    }


@app.get("/workloads/{workload_id}")
def get_workload(workload_id: str, _: None = Depends(verify_api_key)):
    return {
        "workload_id": workload_id,
        "status": "active",
        "svid": f"spiffe://cyberarmor.ai/workload/{workload_id}",
    }


# ── Delegation Endpoints ──────────────────────────────────────────────────────

@app.post("/delegations", response_model=DelegationOut, status_code=201)
def create_delegation(
    body: DelegationCreate,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    chain_id = _new_chain_id()
    delegation = DelegationModel(
        chain_id=chain_id,
        parent_human_id=body.parent_human_id,
        agent_id=body.agent_id,
        scope=body.scope,
        expires_at=body.expires_at,
        status="active",
    )
    db.add(delegation)
    db.commit()
    db.refresh(delegation)
    logger.info("Delegation created: chain_id=%s human=%s agent=%s",
                chain_id, body.parent_human_id, body.agent_id)
    return _delegation_to_out(delegation)


@app.get("/delegations")
def list_delegations(
    parent_human_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """List delegation chains with optional filters."""
    q = db.query(DelegationModel)
    if parent_human_id:
        q = q.filter(DelegationModel.parent_human_id == parent_human_id)
    if agent_id:
        q = q.filter(DelegationModel.agent_id == agent_id)
    if status:
        q = q.filter(DelegationModel.status == status)

    total = q.count()
    rows = q.order_by(DelegationModel.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "delegations": [_delegation_to_out(d).model_dump() for d in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.get("/delegations/{chain_id}", response_model=DelegationOut)
def get_delegation(chain_id: str, db: Session = Depends(get_db), _: None = Depends(verify_api_key)):
    d = db.query(DelegationModel).filter(DelegationModel.chain_id == chain_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Delegation not found")
    return _delegation_to_out(d)


@app.delete("/delegations/{chain_id}")
def revoke_delegation(chain_id: str, db: Session = Depends(get_db), _: None = Depends(verify_api_key)):
    d = db.query(DelegationModel).filter(DelegationModel.chain_id == chain_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Delegation not found")
    d.status = "revoked"
    db.commit()
    return {"chain_id": chain_id, "status": "revoked"}


# ── Health & Metrics ──────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "agent-identity", "version": "1.0.0"}


@app.get("/ready")
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception:
        raise HTTPException(status_code=503, detail="Database not ready")


@app.get("/metrics")
def metrics(db: Session = Depends(get_db)):
    try:
        total_agents = db.query(AgentModel).count()
        active_agents = db.query(AgentModel).filter(AgentModel.status == "active").count()
        total_delegations = db.query(DelegationModel).count()
    except Exception:
        total_agents = active_agents = total_delegations = 0
    lines = [
        "# HELP cyberarmor_agents_total Total registered agents",
        "# TYPE cyberarmor_agents_total gauge",
        f"cyberarmor_agents_total {total_agents}",
        "# HELP cyberarmor_agents_active Active agents",
        "# TYPE cyberarmor_agents_active gauge",
        f"cyberarmor_agents_active {active_agents}",
        "# HELP cyberarmor_delegations_total Total delegations",
        "# TYPE cyberarmor_delegations_total gauge",
        f"cyberarmor_delegations_total {total_delegations}",
    ]
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain")


# ── Private Helpers ───────────────────────────────────────────────────────────

def _get_agent_or_404(db: Session, agent_id: str) -> AgentModel:
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return agent


def _agent_to_out(agent: AgentModel) -> AgentOut:
    tags = agent.tags or {}
    trust_level = tags.get("trust_level", "standard")
    description = tags.get("description")
    return AgentOut(
        agent_id=agent.agent_id,
        display_name=agent.display_name,
        agent_type=agent.agent_type,
        owner_team=agent.owner_team,
        owner_human_id=agent.owner_human_id,
        application=agent.application,
        environment=agent.environment,
        ai_provider=agent.ai_provider,
        model=agent.model,
        framework=agent.framework,
        allowed_tools=agent.allowed_tools or [],
        denied_tools=agent.denied_tools or [],
        sensitivity_tier=agent.sensitivity_tier,
        credential_type=agent.credential_type,
        credential_ttl_seconds=agent.credential_ttl_seconds,
        tags=agent.tags or {},
        status=agent.status,
        tenant_id=agent.tenant_id,
        created_at=agent.created_at,
        last_seen_at=agent.last_seen_at,
        name=agent.display_name,
        trust_level=trust_level,
        capabilities=agent.allowed_tools or [],
        description=description,
    )


def _delegation_to_out(d: DelegationModel) -> DelegationOut:
    return DelegationOut(
        chain_id=d.chain_id,
        parent_human_id=d.parent_human_id,
        agent_id=d.agent_id,
        scope=d.scope or [],
        expires_at=d.expires_at,
        status=d.status,
        created_at=d.created_at,
    )
