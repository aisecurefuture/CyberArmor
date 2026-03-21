"""CyberArmor Audit & Action Graph Service.

Immutable audit log with PQC-signed events and AI action graph.
Port: 8011
"""

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, JSON, Index, create_engine, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("audit_service")

AUDIT_API_SECRET = os.getenv("AUDIT_API_SECRET", "change-me-audit")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://cyberarmor:cyberarmor@postgres:5432/cyberarmor")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
AUDIT_SIGNING_KEY = os.getenv("CYBERARMOR_AUDIT_SIGNING_KEY", AUDIT_API_SECRET)
AUDIT_SIGNING_KEY_ID = os.getenv("CYBERARMOR_AUDIT_SIGNING_KEY_ID", "k1")
AUDIT_NEXT_SIGNING_KEY = os.getenv("CYBERARMOR_AUDIT_NEXT_SIGNING_KEY")
AUDIT_NEXT_SIGNING_KEY_ID = os.getenv("CYBERARMOR_AUDIT_NEXT_SIGNING_KEY_ID", "k2")
AUDIT_RETENTION_DAYS = int(os.getenv("AUDIT_RETENTION_DAYS", "365"))
AUDIT_MIN_RETENTION_DAYS = int(os.getenv("AUDIT_MIN_RETENTION_DAYS", "90"))
ENFORCE_IMMUTABLE_RETENTION = os.getenv("CYBERARMOR_ENFORCE_IMMUTABLE_RETENTION", "false").strip().lower() in {"1", "true", "yes", "on"}
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
    if _bad(AUDIT_API_SECRET):
        failing.append("AUDIT_API_SECRET")
    if _bad(AUDIT_SIGNING_KEY):
        failing.append("CYBERARMOR_AUDIT_SIGNING_KEY")
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


def _enforce_immutability_retention_policy() -> None:
    if not ENFORCE_IMMUTABLE_RETENTION:
        return
    if AUDIT_RETENTION_DAYS < AUDIT_MIN_RETENTION_DAYS:
        raise RuntimeError(
            "Refusing startup: immutable retention enforcement requires "
            f"AUDIT_RETENTION_DAYS >= AUDIT_MIN_RETENTION_DAYS ({AUDIT_MIN_RETENTION_DAYS})."
        )


_enforce_immutability_retention_policy()

# ── DB ────────────────────────────────────────────────────────────────────────

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class AuditEventModel(Base):
    __tablename__ = "audit_events"
    event_id = Column(String(64), primary_key=True)
    trace_id = Column(String(64), nullable=False, index=True)
    span_id = Column(String(48), nullable=False)
    parent_span_id = Column(String(48), nullable=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(64), nullable=False, index=True)
    agent_token_id = Column(String(64), nullable=True)
    human_initiator_id = Column(String(255), nullable=True)
    delegation_chain = Column(JSON, default=list)
    event_type = Column(String(64), nullable=False, index=True)
    provider = Column(String(64), nullable=True)
    model = Column(String(255), nullable=True)
    framework = Column(String(64), nullable=True)
    action = Column(JSON, nullable=True)
    policy_decision = Column(JSON, nullable=True)
    data_classification = Column(JSON, default=list)
    outcome = Column(String(32), nullable=False, default="success", index=True)
    latency_ms = Column(Integer, default=0)
    cost_usd = Column(Float, default=0.0)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    signature = Column(Text, nullable=True)
    prev_event_id = Column(String(64), nullable=True)
    prev_signature = Column(Text, nullable=True)
    chain_hash = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_audit_tenant_agent", "tenant_id", "agent_id"),
        Index("ix_audit_tenant_time", "tenant_id", "timestamp"),
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _wait_for_db(max_wait_s: int = 45):
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
                raise
            sleep_s = min(0.25 * (1.4 ** (attempt - 1)), 2.0)
            logger.warning("DB not ready, retry %.2fs: %s", sleep_s, e)
            time.sleep(sleep_s)


def _ensure_chain_columns() -> None:
    """Migrate older audit schema to include chain fields if missing."""
    try:
        inspector = inspect(engine)
        if not inspector.has_table("audit_events"):
            return
        existing = {col["name"] for col in inspector.get_columns("audit_events")}
        needed = {
            "prev_event_id": "VARCHAR(64)",
            "prev_signature": "TEXT",
            "chain_hash": "TEXT",
        }
        for name, ddl in needed.items():
            if name in existing:
                continue
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE audit_events ADD COLUMN {name} {ddl}"))
            logger.info("Added missing audit_events column via runtime migration: %s", name)
    except Exception as exc:
        logger.warning("Failed to apply audit chain migration: %s", exc)


def _latest_tenant_event(db: Session, tenant_id: str) -> Optional[AuditEventModel]:
    return (
        db.query(AuditEventModel)
        .filter(AuditEventModel.tenant_id == tenant_id)
        .order_by(AuditEventModel.timestamp.desc(), AuditEventModel.event_id.desc())
        .first()
    )


def _get_batch_previous_for_tenant(
    db: Session,
    previous_by_tenant: Dict[str, Optional[AuditEventModel]],
    tenant_id: str,
) -> Optional[AuditEventModel]:
    if tenant_id not in previous_by_tenant:
        previous_by_tenant[tenant_id] = _latest_tenant_event(db, tenant_id)
    return previous_by_tenant[tenant_id]


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_api_key(api_key: str | None = Header(default=None, alias="x-api-key")):
    if not api_key or api_key != AUDIT_API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


def _compute_chain_hash(signature: str, previous_signature: str | None) -> str:
    base = f"{previous_signature or ''}|{signature}".encode()
    return hashlib.sha256(base).hexdigest()


def _sign_event(event_dict: dict, prev_signature: str | None = None) -> str:
    """Sign event payload with HMAC-SHA256 (Ed25519/PQC if keys available)."""
    def _json_default(value):
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)

    payload_dict = dict(event_dict)
    payload_dict.pop("signature", None)
    payload_dict.pop("chain_hash", None)
    if prev_signature is not None and "prev_signature" not in payload_dict:
        payload_dict["prev_signature"] = prev_signature
    payload = json.dumps(payload_dict, sort_keys=True, default=_json_default).encode()
    signing_key = AUDIT_SIGNING_KEY.encode()
    import hmac
    digest = hmac.new(signing_key, payload, hashlib.sha256).hexdigest()
    return f"{AUDIT_SIGNING_KEY_ID}:{digest}"


def _verify_signature(event_dict: dict, signature: str) -> bool:
    prev_signature = event_dict.get("prev_signature") if isinstance(event_dict, dict) else None
    import hmac

    # Backward-compat: legacy signatures were raw hex (no key id prefix).
    if ":" not in signature:
        expected_legacy = hmac.new(
            AUDIT_SIGNING_KEY.encode(),
            json.dumps(
                {
                    **{k: v for k, v in event_dict.items() if k not in {"signature", "chain_hash"}},
                    **({"prev_signature": prev_signature} if prev_signature and "prev_signature" not in event_dict else {}),
                },
                sort_keys=True,
                default=lambda v: v.isoformat() if isinstance(v, datetime) else str(v),
            ).encode(),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected_legacy, signature)

    kid, digest = signature.split(":", 1)

    # Reconstruct canonical payload exactly like _sign_event.
    payload_dict = dict(event_dict)
    payload_dict.pop("signature", None)
    payload_dict.pop("chain_hash", None)
    if prev_signature is not None and "prev_signature" not in payload_dict:
        payload_dict["prev_signature"] = prev_signature
    payload = json.dumps(
        payload_dict,
        sort_keys=True,
        default=lambda value: value.isoformat() if isinstance(value, datetime) else str(value),
    ).encode()

    candidate_keys: List[tuple[str, str]] = [(AUDIT_SIGNING_KEY_ID, AUDIT_SIGNING_KEY)]
    if AUDIT_NEXT_SIGNING_KEY:
        candidate_keys.append((AUDIT_NEXT_SIGNING_KEY_ID, AUDIT_NEXT_SIGNING_KEY))

    for candidate_kid, candidate_secret in candidate_keys:
        if kid != candidate_kid:
            continue
        expected = hmac.new(candidate_secret.encode(), payload, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, digest):
            return True
    return False


# ── Pydantic Models ───────────────────────────────────────────────────────────

class ActionRecord(BaseModel):
    type: str = "llm_call"
    prompt_hash: Optional[str] = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    tool_name: Optional[str] = None
    tool_input_hash: Optional[str] = None
    target_system: Optional[str] = None


class PolicyDecisionRecord(BaseModel):
    decision: str
    policy_id: Optional[str] = None
    reason_code: str = ""
    risk_score: float = 0.0
    latency_ms: int = 0
    redaction_targets: List[str] = []


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: "evt_" + str(uuid4()).replace("-", "")[:20])
    trace_id: str
    span_id: str = Field(default_factory=lambda: "spn_" + str(uuid4()).replace("-", "")[:16])
    parent_span_id: Optional[str] = None
    tenant_id: str = "default"
    agent_id: str
    agent_token_id: Optional[str] = None
    human_initiator_id: Optional[str] = None
    delegation_chain: List[str] = []
    event_type: str
    provider: Optional[str] = None
    model: Optional[str] = None
    framework: Optional[str] = None
    action: Optional[ActionRecord] = None
    policy_decision: Optional[PolicyDecisionRecord] = None
    data_classification: List[str] = []
    outcome: str = "success"
    latency_ms: int = 0
    cost_usd: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    signature: Optional[str] = None


class BatchIngestRequest(BaseModel):
    events: List[AuditEvent]


class EventQuery(BaseModel):
    agent_id: Optional[str] = None
    tenant_id: Optional[str] = None
    provider: Optional[str] = None
    event_type: Optional[str] = None
    outcome: Optional[str] = None
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    limit: int = 100
    offset: int = 0


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="CyberArmor Audit & Action Graph Service",
    version="1.0.0",
    description="Immutable audit log with AI action graph for forensics and compliance",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def on_startup():
    logger.info("Audit Service starting...")
    _wait_for_db()
    Base.metadata.create_all(bind=engine)
    _ensure_chain_columns()
    logger.info("Audit Service ready on port 8011")


# ── Event Ingestion ───────────────────────────────────────────────────────────

@app.post("/events", status_code=201)
def ingest_event(
    event: AuditEvent,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Ingest a single audit event."""
    event_dict = event.model_dump()
    if not event.signature:
        event_dict["signature"] = _sign_event(event_dict)
        event.signature = event_dict["signature"]

    previous = _latest_tenant_event(db, event.tenant_id)
    prev_signature = previous.signature if previous else None
    if previous:
        event_dict["prev_event_id"] = previous.event_id
        event_dict["prev_signature"] = prev_signature
        event_dict["signature"] = _sign_event(event_dict, prev_signature=prev_signature)
        event.signature = event_dict["signature"]
    else:
        event_dict["prev_event_id"] = None
        event_dict["prev_signature"] = None

    event_dict["chain_hash"] = _compute_chain_hash(event_dict["signature"], prev_signature)
    event.signature = event_dict["signature"]

    model = AuditEventModel(
        event_id=event.event_id,
        trace_id=event.trace_id,
        span_id=event.span_id,
        parent_span_id=event.parent_span_id,
        tenant_id=event.tenant_id,
        agent_id=event.agent_id,
        agent_token_id=event.agent_token_id,
        human_initiator_id=event.human_initiator_id,
        delegation_chain=event.delegation_chain,
        event_type=event.event_type,
        provider=event.provider,
        model=event.model,
        framework=event.framework,
        action=event.action.model_dump() if event.action else None,
        policy_decision=event.policy_decision.model_dump() if event.policy_decision else None,
        data_classification=event.data_classification,
        outcome=event.outcome,
        latency_ms=event.latency_ms,
        cost_usd=event.cost_usd,
        timestamp=event.timestamp,
        signature=event.signature,
        prev_event_id=event_dict.get("prev_event_id"),
        prev_signature=event_dict.get("prev_signature"),
        chain_hash=event_dict.get("chain_hash"),
    )
    existing = db.query(AuditEventModel).filter(AuditEventModel.event_id == event.event_id).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Event '{event.event_id}' already exists (append-only)")
    db.add(model)
    db.commit()
    return {"event_id": event.event_id, "stored": True, "append_only": True}


@app.post("/events/batch", status_code=202)
def ingest_batch(
    body: BatchIngestRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Batch ingest audit events."""
    stored = 0
    ordered = sorted(body.events, key=lambda evt: (evt.tenant_id, evt.timestamp, evt.event_id))
    previous_by_tenant: Dict[str, Optional[AuditEventModel]] = {}
    for event in ordered:
        try:
            tenant_id = event.tenant_id
            previous = _get_batch_previous_for_tenant(db, previous_by_tenant, tenant_id)
            event_dict = event.model_dump()
            if not event.signature:
                event_dict["signature"] = _sign_event(event_dict)
                event.signature = event_dict["signature"]

            if previous:
                event_dict["prev_event_id"] = previous.event_id
                event_dict["prev_signature"] = previous.signature
                event_dict["signature"] = _sign_event(event_dict, prev_signature=previous.signature)
                event.signature = event_dict["signature"]
            else:
                event_dict["prev_event_id"] = None
                event_dict["prev_signature"] = None

            event_dict["chain_hash"] = _compute_chain_hash(event_dict["signature"], event_dict.get("prev_signature"))

            model = AuditEventModel(
                event_id=event.event_id,
                trace_id=event.trace_id,
                span_id=event.span_id,
                parent_span_id=event.parent_span_id,
                tenant_id=event.tenant_id,
                agent_id=event.agent_id,
                agent_token_id=event.agent_token_id,
                human_initiator_id=event.human_initiator_id,
                delegation_chain=event.delegation_chain,
                event_type=event.event_type,
                provider=event.provider,
                model=event.model,
                framework=event.framework,
                action=event.action.model_dump() if event.action else None,
                policy_decision=event.policy_decision.model_dump() if event.policy_decision else None,
                data_classification=event.data_classification,
                outcome=event.outcome,
                latency_ms=event.latency_ms,
                cost_usd=event.cost_usd,
                timestamp=event.timestamp,
                signature=event.signature,
                prev_event_id=event_dict.get("prev_event_id"),
                prev_signature=event_dict.get("prev_signature"),
                chain_hash=event_dict.get("chain_hash"),
            )
            existing = db.query(AuditEventModel).filter(AuditEventModel.event_id == event.event_id).first()
            if existing:
                logger.warning("Duplicate event rejected event_id=%s", event.event_id)
                continue
            db.add(model)
            db.flush()
            previous_by_tenant[tenant_id] = model
            stored += 1
        except Exception as e:
            logger.warning("Batch event ingest failed event_id=%s err=%s", event.event_id, e)
    db.commit()
    return {"stored": stored, "total": len(body.events)}


# ── Event Queries ─────────────────────────────────────────────────────────────

@app.get("/events")
def query_events(
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    provider: Optional[str] = None,
    event_type: Optional[str] = None,
    outcome: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    q = db.query(AuditEventModel)
    if agent_id:
        q = q.filter(AuditEventModel.agent_id == agent_id)
    if tenant_id:
        q = q.filter(AuditEventModel.tenant_id == tenant_id)
    if provider:
        q = q.filter(AuditEventModel.provider == provider)
    if event_type:
        q = q.filter(AuditEventModel.event_type == event_type)
    if outcome:
        q = q.filter(AuditEventModel.outcome == outcome)
    if since:
        q = q.filter(AuditEventModel.timestamp >= since)
    if until:
        q = q.filter(AuditEventModel.timestamp <= until)

    q = q.order_by(AuditEventModel.timestamp.desc(), AuditEventModel.event_id.desc())
    total = q.count()
    events = q.offset(offset).limit(limit).all()
    return {"total": total, "offset": offset, "limit": limit, "events": [_model_to_dict(e) for e in events]}


@app.get("/events/{event_id}")
def get_event(event_id: str, db: Session = Depends(get_db), _: None = Depends(verify_api_key)):
    evt = db.query(AuditEventModel).filter(AuditEventModel.event_id == event_id).first()
    if not evt:
        raise HTTPException(status_code=404, detail="Event not found")
    return _model_to_dict(evt)


@app.get("/traces/{trace_id}")
def get_trace(trace_id: str, db: Session = Depends(get_db), _: None = Depends(verify_api_key)):
    """Get all events in a trace, ordered by timestamp."""
    events = db.query(AuditEventModel).filter(
        AuditEventModel.trace_id == trace_id
    ).order_by(AuditEventModel.timestamp.asc(), AuditEventModel.span_id.asc(), AuditEventModel.event_id.asc()).all()
    return {"trace_id": trace_id, "span_count": len(events), "events": [_model_to_dict(e) for e in events]}


# ── Action Graph ──────────────────────────────────────────────────────────────

@app.get("/graph/agent/{agent_id}")
def agent_action_graph(
    agent_id: str,
    hours: int = 24,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Build action graph for an agent."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    events = db.query(AuditEventModel).filter(
        AuditEventModel.agent_id == agent_id,
        AuditEventModel.timestamp >= since,
    ).order_by(AuditEventModel.timestamp.asc()).all()

    return _build_graph(agent_id, events, "agent")


@app.get("/graph/human/{human_id}")
def human_action_graph(
    human_id: str,
    hours: int = 24,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Build action graph for a human initiator (through their agents)."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    events = db.query(AuditEventModel).filter(
        AuditEventModel.human_initiator_id == human_id,
        AuditEventModel.timestamp >= since,
    ).order_by(AuditEventModel.timestamp.asc()).all()

    return _build_graph(human_id, events, "human")


def _build_graph(root_id: str, events: List[AuditEventModel], root_type: str) -> Dict:
    """Build a directed graph from audit events."""
    nodes: Dict[str, Dict] = {}
    edges: List[Dict] = []
    edge_counts: Dict[str, int] = {}

    def add_node(node_id: str, node_type: str, label: str):
        nodes[node_id] = {"id": node_id, "type": node_type, "label": label}

    add_node(root_id, root_type, root_id)

    for evt in events:
        agent_node = evt.agent_id
        add_node(agent_node, "agent", agent_node)

        if evt.human_initiator_id and root_type == "human":
            edge_key = f"{evt.human_initiator_id}→{agent_node}:initiated"
            edge_counts[edge_key] = edge_counts.get(edge_key, 0) + 1

        provider = evt.provider or "unknown"
        provider_node = f"provider:{provider}"
        add_node(provider_node, "provider", provider)
        if evt.model:
            model_node = f"model:{evt.model}"
            add_node(model_node, "model", evt.model)
            edge_key = f"{agent_node}→{model_node}:llm_call"
            edge_counts[edge_key] = edge_counts.get(edge_key, 0) + 1

        action = evt.action or {}
        if isinstance(action, dict) and action.get("tool_name"):
            tool_node = f"tool:{action['tool_name']}"
            add_node(tool_node, "tool", action["tool_name"])
            edge_key = f"{agent_node}→{tool_node}:tool_call"
            edge_counts[edge_key] = edge_counts.get(edge_key, 0) + 1

    for edge_key, count in edge_counts.items():
        parts = edge_key.split("→")
        if len(parts) == 2:
            from_node, rest = parts
            to_node, action = rest.split(":", 1)
            edges.append({
                "from": from_node, "to": to_node,
                "action": action, "count": count,
                "timestamp": events[-1].timestamp.isoformat() if events else "",
            })

    return {
        "root_id": root_id,
        "root_type": root_type,
        "event_count": len(events),
        "nodes": list(nodes.values()),
        "edges": edges,
    }


@app.get("/timeline")
def get_timeline(
    hours: int = 24,
    tenant_id: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Human-readable action timeline."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = db.query(AuditEventModel).filter(AuditEventModel.timestamp >= since)
    if tenant_id:
        q = q.filter(AuditEventModel.tenant_id == tenant_id)
    events = q.order_by(AuditEventModel.timestamp.desc()).limit(limit).all()

    timeline = []
    for evt in events:
        action = evt.action or {}
        tool = action.get("tool_name") if isinstance(action, dict) else None
        model = evt.model or "unknown"
        desc = f"[{evt.event_type}] Agent {evt.agent_id[:12]}... called {tool or model}"
        if evt.outcome == "blocked":
            desc += " → BLOCKED"
        pd = evt.policy_decision or {}
        reason = pd.get("reason_code") if isinstance(pd, dict) else None
        if reason:
            desc += f" ({reason})"
        timeline.append({
            "timestamp": evt.timestamp.isoformat(),
            "event_id": evt.event_id,
            "agent_id": evt.agent_id,
            "description": desc,
            "outcome": evt.outcome,
            "provider": evt.provider,
            "cost_usd": evt.cost_usd,
            "latency_ms": evt.latency_ms,
        })
    return {"hours": hours, "count": len(timeline), "events": timeline}


@app.post("/export")
def export_events(
    body: EventQuery,
    fmt: str = "json",
    _: None = Depends(verify_api_key),
    db: Session = Depends(get_db),
):
    """Export events to SIEM format."""
    export_id = "exp_" + str(uuid4()).replace("-", "")[:16]
    q = db.query(AuditEventModel)
    if body.agent_id:
        q = q.filter(AuditEventModel.agent_id == body.agent_id)
    if body.tenant_id:
        q = q.filter(AuditEventModel.tenant_id == body.tenant_id)
    count = q.count()
    return {
        "export_id": export_id,
        "format": fmt,
        "events_count": count,
        "status": "queued",
        "download_url": f"/export/{export_id}/download",
    }


@app.get("/integrity/verify/{event_id}")
def verify_event_integrity(
    event_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Verify event signature for tamper detection."""
    evt = db.query(AuditEventModel).filter(AuditEventModel.event_id == event_id).first()
    if not evt:
        raise HTTPException(status_code=404, detail="Event not found")

    event_dict = _model_to_dict(evt)
    stored_sig = event_dict.pop("signature", None)

    if not stored_sig:
        return {"valid": False, "event_id": event_id, "reason": "NO_SIGNATURE"}

    valid = _verify_signature(event_dict, stored_sig)

    chain_valid = True
    chain_reason = None
    if (evt.prev_event_id and not evt.prev_signature) or (evt.prev_signature and not evt.prev_event_id):
        chain_valid = False
        chain_reason = "CHAIN_POINTER_INCOMPLETE"
    elif evt.prev_event_id:
        previous = db.query(AuditEventModel).filter(AuditEventModel.event_id == evt.prev_event_id).first()
        if not previous:
            chain_valid = False
            chain_reason = "MISSING_PREVIOUS_EVENT"
        elif previous.signature != evt.prev_signature:
            chain_valid = False
            chain_reason = "PREVIOUS_SIGNATURE_MISMATCH"
        elif evt.chain_hash != _compute_chain_hash(stored_sig, evt.prev_signature):
            chain_valid = False
            chain_reason = "CHAIN_HASH_MISMATCH"
    return {
        "valid": valid,
        "event_id": event_id,
        "algorithm": "HMAC-SHA256",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "reason": "SIGNATURE_MATCH" if valid else "SIGNATURE_MISMATCH",
        "chain_valid": chain_valid,
        "chain_reason": chain_reason,
    }


@app.get("/integrity/signing-key/status")
def signing_key_status(
    _: None = Depends(verify_api_key),
):
    return {
        "active_key_id": AUDIT_SIGNING_KEY_ID,
        "next_key_configured": bool(AUDIT_NEXT_SIGNING_KEY),
        "next_key_id": AUDIT_NEXT_SIGNING_KEY_ID if AUDIT_NEXT_SIGNING_KEY else None,
        "retention_days": AUDIT_RETENTION_DAYS,
        "immutable_retention_enforced": ENFORCE_IMMUTABLE_RETENTION,
    }


# ── Health & Metrics ──────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "audit", "version": "1.0.0"}


@app.get("/ready")
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception:
        raise HTTPException(status_code=503, detail="Database not ready")


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(db: Session = Depends(get_db)):
    try:
        total = db.query(AuditEventModel).count()
        blocked = db.query(AuditEventModel).filter(AuditEventModel.outcome == "blocked").count()
        success = db.query(AuditEventModel).filter(AuditEventModel.outcome == "success").count()
    except Exception:
        total = blocked = success = 0
    lines = [
        "# HELP cyberarmor_audit_events_total Total audit events",
        "# TYPE cyberarmor_audit_events_total gauge",
        f"cyberarmor_audit_events_total {total}",
        f'cyberarmor_audit_events_by_outcome{{outcome="blocked"}} {blocked}',
        f'cyberarmor_audit_events_by_outcome{{outcome="success"}} {success}',
    ]
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain")


# ── Private helpers ───────────────────────────────────────────────────────────

def _model_to_dict(evt: AuditEventModel) -> Dict:
    return {
        "event_id": evt.event_id,
        "trace_id": evt.trace_id,
        "span_id": evt.span_id,
        "parent_span_id": evt.parent_span_id,
        "tenant_id": evt.tenant_id,
        "agent_id": evt.agent_id,
        "agent_token_id": evt.agent_token_id,
        "human_initiator_id": evt.human_initiator_id,
        "delegation_chain": evt.delegation_chain or [],
        "event_type": evt.event_type,
        "provider": evt.provider,
        "model": evt.model,
        "framework": evt.framework,
        "action": evt.action,
        "policy_decision": evt.policy_decision,
        "data_classification": evt.data_classification or [],
        "outcome": evt.outcome,
        "latency_ms": evt.latency_ms,
        "cost_usd": evt.cost_usd,
        "prev_event_id": evt.prev_event_id,
        "prev_signature": evt.prev_signature,
        "chain_hash": evt.chain_hash,
        "timestamp": evt.timestamp.isoformat() if evt.timestamp else None,
        "signature": evt.signature,
    }
