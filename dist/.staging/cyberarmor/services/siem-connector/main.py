"""
CyberArmor.ai Protect - SIEM Connector Service

Receives security events from all CyberArmor.ai services and routes them
to configured SIEM outputs. Supports event normalization, buffering,
batching, and per-tenant SIEM destination configuration.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from outputs.base import SIEMOutput
from outputs.splunk import SplunkOutput
from outputs.sentinel import SentinelOutput
from outputs.qradar import QRadarOutput
from outputs.elastic import ElasticOutput
from outputs.google_secops import GoogleSecOpsOutput
from outputs.syslog_cef import SyslogCEFOutput

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("siem-connector")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SIEM_API_SECRET = os.getenv("SIEM_API_SECRET", "change-me-siem")
BATCH_SIZE = int(os.getenv("SIEM_BATCH_SIZE", "100"))
FLUSH_INTERVAL_SECONDS = float(os.getenv("SIEM_FLUSH_INTERVAL", "5.0"))

# ---------------------------------------------------------------------------
# Output registry
# ---------------------------------------------------------------------------
OUTPUT_TYPES: dict[str, type[SIEMOutput]] = {
    "splunk": SplunkOutput,
    "sentinel": SentinelOutput,
    "qradar": QRadarOutput,
    "elastic": ElasticOutput,
    "google_secops": GoogleSecOpsOutput,
    "syslog_cef": SyslogCEFOutput,
}

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityEvent(BaseModel):
    """Incoming security event from any CyberArmor.ai service."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tenant_id: str = "default"
    source_service: str = "unknown"
    event_type: str = "generic"
    severity: SeverityLevel = SeverityLevel.INFO
    title: str = ""
    description: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    raw: Optional[dict[str, Any]] = None


class NormalizedEvent(BaseModel):
    """Common schema for all SIEM outputs."""
    event_id: str
    timestamp: str
    ingested_at: str
    tenant_id: str
    source_service: str
    event_type: str
    severity: str
    severity_numeric: int
    title: str
    description: str
    details: dict[str, Any]
    tags: list[str]
    product: str = "CyberArmor.ai Protect"
    product_version: str = "1.0.0"
    schema_version: str = "1.0"


class OutputConfigRequest(BaseModel):
    """Request body for configuring a SIEM output."""
    tenant_id: str = "default"
    output_type: str
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class OutputConfigResponse(BaseModel):
    output_id: str
    tenant_id: str
    output_type: str
    enabled: bool
    created_at: str
    last_test: Optional[str] = None
    status: str = "configured"


class TestEventRequest(BaseModel):
    """Request body for sending a test event."""
    tenant_id: str = "default"
    output_id: Optional[str] = None


class EventBatchRequest(BaseModel):
    """Submit multiple events at once."""
    events: list[SecurityEvent]


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------
SEVERITY_MAP: dict[str, int] = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
}

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="CyberArmor.ai Protect - SIEM Connector",
    description="Routes security events to enterprise SIEM platforms.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------
# tenant_id -> list[output_config]
tenant_outputs: dict[str, list[dict[str, Any]]] = defaultdict(list)
# output_id -> SIEMOutput instance
output_instances: dict[str, SIEMOutput] = {}
# Buffered events per tenant
event_buffer: dict[str, list[NormalizedEvent]] = defaultdict(list)
# Metrics
metrics: dict[str, int] = {
    "events_received": 0,
    "events_sent": 0,
    "events_failed": 0,
    "batches_flushed": 0,
}


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------
async def verify_api_key(api_key: Optional[str] = Security(api_key_header)) -> str:
    if api_key != SIEM_API_SECRET:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return api_key


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def normalize_event(event: SecurityEvent) -> NormalizedEvent:
    """Convert an incoming SecurityEvent to the normalized common schema."""
    return NormalizedEvent(
        event_id=event.event_id,
        timestamp=event.timestamp,
        ingested_at=datetime.now(timezone.utc).isoformat(),
        tenant_id=event.tenant_id,
        source_service=event.source_service,
        event_type=event.event_type,
        severity=event.severity.value,
        severity_numeric=SEVERITY_MAP.get(event.severity.value, 0),
        title=event.title,
        description=event.description,
        details=event.details,
        tags=event.tags,
    )


# ---------------------------------------------------------------------------
# Buffer / Batch logic
# ---------------------------------------------------------------------------
async def flush_buffer(tenant_id: str) -> int:
    """Flush buffered events for a tenant to all configured outputs."""
    events = event_buffer.pop(tenant_id, [])
    if not events:
        return 0

    outputs = tenant_outputs.get(tenant_id, [])
    sent = 0
    for out_cfg in outputs:
        if not out_cfg.get("enabled", True):
            continue
        output_id = out_cfg["output_id"]
        instance = output_instances.get(output_id)
        if instance is None:
            continue
        try:
            event_dicts = [e.model_dump() for e in events]
            await instance.send_batch(event_dicts)
            sent += len(events)
            logger.info(
                "Flushed %d events to output %s (%s) for tenant %s",
                len(events),
                output_id,
                out_cfg["output_type"],
                tenant_id,
            )
        except Exception:
            metrics["events_failed"] += len(events)
            logger.exception(
                "Failed to flush events to output %s for tenant %s",
                output_id,
                tenant_id,
            )

    metrics["events_sent"] += sent
    metrics["batches_flushed"] += 1
    return sent


async def buffer_event(event: NormalizedEvent) -> None:
    """Add an event to the tenant buffer and flush if threshold reached."""
    tenant_id = event.tenant_id
    event_buffer[tenant_id].append(event)
    if len(event_buffer[tenant_id]) >= BATCH_SIZE:
        await flush_buffer(tenant_id)


async def periodic_flush() -> None:
    """Background task that flushes all tenant buffers periodically."""
    while True:
        await asyncio.sleep(FLUSH_INTERVAL_SECONDS)
        tenant_ids = list(event_buffer.keys())
        for tid in tenant_ids:
            try:
                await flush_buffer(tid)
            except Exception:
                logger.exception("Error during periodic flush for tenant %s", tid)


# ---------------------------------------------------------------------------
# Startup / Shutdown
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def on_startup() -> None:
    logger.info("SIEM Connector starting up on port 8005")
    asyncio.create_task(periodic_flush())


@app.on_event("shutdown")
async def on_shutdown() -> None:
    logger.info("SIEM Connector shutting down - flushing remaining buffers")
    for tid in list(event_buffer.keys()):
        await flush_buffer(tid)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "service": "siem-connector",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics,
        "configured_outputs": sum(len(v) for v in tenant_outputs.values()),
        "buffered_events": sum(len(v) for v in event_buffer.values()),
    }


@app.post("/events")
async def receive_events(
    request: Request,
    _key: str = Security(verify_api_key),
) -> dict[str, Any]:
    """Receive one or more security events and route to SIEM outputs."""
    body = await request.json()

    # Accept either a single event or a list
    if isinstance(body, list):
        events = [SecurityEvent(**e) for e in body]
    else:
        events = [SecurityEvent(**body)]

    metrics["events_received"] += len(events)
    normalized: list[NormalizedEvent] = []

    for event in events:
        ne = normalize_event(event)
        normalized.append(ne)
        await buffer_event(ne)

    return {
        "accepted": len(normalized),
        "event_ids": [e.event_id for e in normalized],
    }


@app.post("/events/batch")
async def receive_events_batch(
    body: EventBatchRequest,
    _key: str = Security(verify_api_key),
) -> dict[str, Any]:
    metrics["events_received"] += len(body.events)
    normalized: list[NormalizedEvent] = []
    for event in body.events:
        ne = normalize_event(event)
        normalized.append(ne)
        await buffer_event(ne)
    return {"accepted": len(normalized), "event_ids": [e.event_id for e in normalized]}


@app.post("/ingest")
async def ingest_compat(
    request: Request,
    _key: str = Security(verify_api_key),
) -> dict[str, Any]:
    """Compatibility endpoint for services that post raw telemetry events."""
    body = await request.json()
    events_raw = body if isinstance(body, list) else [body]
    events: list[SecurityEvent] = []
    for raw in events_raw:
        if not isinstance(raw, dict):
            continue
        normalized_raw = {
            "event_id": raw.get("event_id") or raw.get("request_id") or str(uuid.uuid4()),
            "timestamp": raw.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "tenant_id": raw.get("tenant_id", "default"),
            "source_service": raw.get("source_service", raw.get("service", "proxy")),
            "event_type": raw.get("event_type", "telemetry"),
            "severity": raw.get("severity", "info"),
            "title": raw.get("title", raw.get("event_type", "Telemetry Event")),
            "description": raw.get("description", raw.get("reason", "")),
            "details": raw,
            "tags": raw.get("tags", []),
            "raw": raw,
        }
        events.append(SecurityEvent(**normalized_raw))

    metrics["events_received"] += len(events)
    normalized: list[NormalizedEvent] = []
    for event in events:
        ne = normalize_event(event)
        normalized.append(ne)
        await buffer_event(ne)

    return {"accepted": len(normalized), "event_ids": [e.event_id for e in normalized]}


@app.get("/outputs")
async def list_outputs(
    tenant_id: Optional[str] = None,
    _key: str = Security(verify_api_key),
) -> dict[str, Any]:
    """List configured SIEM outputs, optionally filtered by tenant."""
    if tenant_id:
        configs = tenant_outputs.get(tenant_id, [])
    else:
        configs = []
        for tid_configs in tenant_outputs.values():
            configs.extend(tid_configs)

    return {
        "outputs": configs,
        "available_types": list(OUTPUT_TYPES.keys()),
    }


@app.post("/outputs/configure")
async def configure_output(
    req: OutputConfigRequest,
    _key: str = Security(verify_api_key),
) -> OutputConfigResponse:
    """Configure a new SIEM output for a tenant."""
    if req.output_type not in OUTPUT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown output type '{req.output_type}'. "
            f"Available: {list(OUTPUT_TYPES.keys())}",
        )

    output_cls = OUTPUT_TYPES[req.output_type]
    output_id = f"{req.tenant_id}_{req.output_type}_{uuid.uuid4().hex[:8]}"

    try:
        instance = output_cls(config=req.config)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid configuration for {req.output_type}: {exc}",
        )

    output_instances[output_id] = instance
    cfg = {
        "output_id": output_id,
        "tenant_id": req.tenant_id,
        "output_type": req.output_type,
        "enabled": req.enabled,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "config_keys": list(req.config.keys()),
        "status": "configured",
    }
    tenant_outputs[req.tenant_id].append(cfg)

    logger.info(
        "Configured output %s (%s) for tenant %s",
        output_id,
        req.output_type,
        req.tenant_id,
    )

    return OutputConfigResponse(**cfg)


@app.post("/events/test")
async def send_test_event(
    req: TestEventRequest,
    _key: str = Security(verify_api_key),
) -> dict[str, Any]:
    """Send a test event to verify SIEM connectivity."""
    test_event = SecurityEvent(
        tenant_id=req.tenant_id,
        source_service="siem-connector",
        event_type="test",
        severity=SeverityLevel.INFO,
        title="CyberArmor.ai SIEM Connector Test Event",
        description="This is a test event to verify SIEM connectivity.",
        details={"test": True, "generated_at": datetime.now(timezone.utc).isoformat()},
        tags=["test", "connectivity-check"],
    )

    normalized = normalize_event(test_event)
    event_dict = normalized.model_dump()
    results: list[dict[str, Any]] = []

    outputs = tenant_outputs.get(req.tenant_id, [])
    if not outputs:
        raise HTTPException(
            status_code=404,
            detail=f"No outputs configured for tenant '{req.tenant_id}'",
        )

    for out_cfg in outputs:
        output_id = out_cfg["output_id"]
        if req.output_id and output_id != req.output_id:
            continue
        instance = output_instances.get(output_id)
        if instance is None:
            results.append({
                "output_id": output_id,
                "success": False,
                "error": "Output instance not found",
            })
            continue
        try:
            conn_ok = await instance.test_connection()
            if conn_ok:
                await instance.send_event(event_dict)
            results.append({
                "output_id": output_id,
                "output_type": out_cfg["output_type"],
                "connection_test": conn_ok,
                "event_sent": conn_ok,
            })
        except Exception as exc:
            results.append({
                "output_id": output_id,
                "output_type": out_cfg["output_type"],
                "connection_test": False,
                "event_sent": False,
                "error": str(exc),
            })

    return {
        "test_event_id": test_event.event_id,
        "results": results,
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8005, log_level="info")
