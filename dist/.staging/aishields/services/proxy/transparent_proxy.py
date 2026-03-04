"""AIShields Transparent Proxy Service.

Custom transparent proxy built on mitmproxy's Python API. Intercepts HTTP/HTTPS
traffic, routes requests through AI content inspection, and enforces policy-based
allow/block decisions. All inspected traffic is logged to the telemetry pipeline.

Supports both transparent and explicit proxy modes. Integrates with the AIShields
Policy Service for enforcement decisions and the Detection Service for deep
content analysis.

Usage (transparent mode):
    mitmdump --mode transparent --listen-port 8080 -s transparent_proxy.py

Usage (explicit mode):
    mitmdump --mode regular --listen-port 8080 -s transparent_proxy.py

Management API (runs alongside the proxy):
    uvicorn transparent_proxy:management_app --host 0.0.0.0 --port 8081
"""

import asyncio
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx
from mitmproxy import ctx, http, options
from mitmproxy.tools import dump

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("aishields.proxy")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s [%(funcName)s] %(message)s",
)

# ---------------------------------------------------------------------------
# Configuration (all overridable via environment variables)
# ---------------------------------------------------------------------------
AISR_RUNTIME_URL = os.getenv("AISR_RUNTIME_URL", "http://runtime:8000")

POLICY_SERVICE_URL = os.getenv("POLICY_SERVICE_URL", "http://policy:8001")
DETECTION_SERVICE_URL = os.getenv("DETECTION_SERVICE_URL", "http://detection:8002")

# Canonical secrets (support both prefixed and legacy env vars)
AISHIELDS_POLICY_API_SECRET = os.getenv("AISHIELDS_POLICY_API_SECRET")
AISHIELDS_POLICY_API_SECRET = os.getenv("AISHIELDS_POLICY_API_SECRET")
POLICY_API_SECRET = os.getenv("POLICY_API_SECRET") or os.getenv("POLICY_API_KEY")

AISHIELDS_DETECTION_API_SECRET = os.getenv("AISHIELDS_DETECTION_API_SECRET")
AISHIELDS_DETECTION_API_SECRET = os.getenv("AISHIELDS_DETECTION_API_SECRET")
DETECTION_API_SECRET = os.getenv("DETECTION_API_SECRET") or os.getenv("DETECTION_API_KEY")
TELEMETRY_ENDPOINT = os.getenv("TELEMETRY_ENDPOINT", "http://siem-connector:8005/ingest")
TELEMETRY_API_KEY = os.getenv("TELEMETRY_API_KEY", "change-me-telemetry")
TENANT_ID = os.getenv("TENANT_ID", "default")
PROXY_MODE = os.getenv("PROXY_MODE", "transparent")  # transparent | explicit
PROXY_LISTEN_PORT = int(os.getenv("PROXY_LISTEN_PORT", "8080"))
PROXY_LISTEN_HOST = os.getenv("PROXY_LISTEN_HOST", "0.0.0.0")
CA_CERT_PATH = os.getenv("CA_CERT_PATH", "/etc/aishields/ca/ca-cert.pem")
CA_KEY_PATH = os.getenv("CA_KEY_PATH", "/etc/aishields/ca/ca-key.pem")
MAX_BODY_SIZE = int(os.getenv("MAX_BODY_SIZE", str(10 * 1024 * 1024)))  # 10 MB
INSPECTION_TIMEOUT = float(os.getenv("INSPECTION_TIMEOUT", "5.0"))
# Action on policy/detection service failure: "allow" or "block"
FAIL_OPEN = os.getenv("FAIL_OPEN", "true").lower() == "true"
DEFAULT_PROXY_RUNTIME_MODE = os.getenv("DEFAULT_PROXY_RUNTIME_MODE", "mitm").lower()
TENANT_MODE_CACHE_TTL_SECONDS = int(os.getenv("TENANT_MODE_CACHE_TTL_SECONDS", "60"))


def _pick(*vals: Optional[str]) -> Optional[str]:
    for v in vals:
        if v:
            return v
    return None


POLICY_SECRET = _pick(AISHIELDS_POLICY_API_SECRET, AISHIELDS_POLICY_API_SECRET, POLICY_API_SECRET)
DETECTION_SECRET = _pick(AISHIELDS_DETECTION_API_SECRET, AISHIELDS_DETECTION_API_SECRET, DETECTION_API_SECRET)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class InspectionResult:
    """Result from content inspection pipeline."""
    request_id: str
    action: str = "allow"  # allow | block | warn | monitor
    reason: str = ""
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    risk_score: float = 0.0
    detections: List[Dict[str, Any]] = field(default_factory=list)
    latency_ms: float = 0.0


@dataclass
class TrafficLogEntry:
    """Structured telemetry log entry for every inspected request."""
    request_id: str
    timestamp: str
    client_ip: str
    method: str
    url: str
    host: str
    request_content_type: Optional[str] = None
    request_body_size: int = 0
    response_status: Optional[int] = None
    response_content_type: Optional[str] = None
    response_body_size: int = 0
    action: str = "allow"
    reason: str = ""
    policy_id: Optional[str] = None
    risk_score: float = 0.0
    detections: List[Dict[str, Any]] = field(default_factory=list)
    inspection_latency_ms: float = 0.0
    tenant_id: str = "default"
    proxy_mode: str = "transparent"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": "proxy_traffic",
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "client_ip": self.client_ip,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "request_content_type": self.request_content_type,
            "request_body_size": self.request_body_size,
            "response_status": self.response_status,
            "response_content_type": self.response_content_type,
            "response_body_size": self.response_body_size,
            "action": self.action,
            "reason": self.reason,
            "policy_id": self.policy_id,
            "risk_score": self.risk_score,
            "detections": self.detections,
            "inspection_latency_ms": self.inspection_latency_ms,
            "tenant_id": self.tenant_id,
            "proxy_mode": self.proxy_mode,
        }


# ---------------------------------------------------------------------------
# HTTP clients (shared across the proxy lifetime)
# ---------------------------------------------------------------------------
_http_client: Optional[httpx.AsyncClient] = None
_tenant_mode_cache: Dict[str, tuple[str, float]] = {}


def _get_http_client() -> httpx.AsyncClient:
    """Lazy-initialise a shared async HTTP client."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(INSPECTION_TIMEOUT, connect=3.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
    return _http_client


# ---------------------------------------------------------------------------
# Policy Service integration
# ---------------------------------------------------------------------------

async def evaluate_policy(
    tenant_id: str,
    request_url: str,
    method: str,
    headers: Dict[str, str],
    body_snippet: str,
    client_ip: str,
) -> Optional[Dict[str, Any]]:
    """Call the Policy Service to evaluate the request against active policies.

    Returns the first matching policy result or None if no policy matched.
    """
    client = _get_http_client()
    payload = {
        "tenant_id": tenant_id,
        "context": {
            "request": {
                "url": request_url,
                "method": method,
                "host": _extract_host(request_url),
                "headers": headers,
                "body_snippet": body_snippet[:2048],
            },
            "user": {"client_ip": client_ip},
        },
    }
    try:
        resp = await client.post(
            f"{POLICY_SERVICE_URL}/evaluate",
            json=payload,
            headers={"x-api-key": POLICY_SECRET or "", "Content-Type": "application/json"},
        )
        if resp.status_code == 200:
            return resp.json()
        logger.warning(
            "policy_service_error status=%d body=%s",
            resp.status_code,
            resp.text[:256],
        )
    except httpx.TimeoutException:
        logger.error("policy_service_timeout url=%s", request_url)
    except Exception as exc:
        logger.error("policy_service_exception err=%s", exc)
    return None


# ---------------------------------------------------------------------------
# Detection Service integration
# ---------------------------------------------------------------------------

async def scan_content(
    tenant_id: str,
    content: str,
    direction: str = "request",
    content_type: str = "text/plain",
    request_url: str = "",
) -> Optional[Dict[str, Any]]:
    """Send content to the Detection Service for deep analysis.

    Args:
        content: The body text to scan.
        direction: 'request' or 'response' to indicate traffic direction.
        content_type: MIME type of the content.
        request_url: The URL associated with this content for context.

    Returns:
        Detection results dict or None on failure.
    """
    if not content or len(content.strip()) == 0:
        return None

    client = _get_http_client()
    payload = {
        "content": content[:MAX_BODY_SIZE],
        "direction": direction,
        "content_type": content_type,
        "source_url": request_url,
        "tenant_id": tenant_id,
    }
    try:
        resp = await client.post(
            f"{DETECTION_SERVICE_URL}/scan",
            json=payload,
            headers={
                "x-api-key": DETECTION_SECRET or "",
                "Content-Type": "application/json",
            },
        )
        if resp.status_code == 200:
            return resp.json()
        logger.warning(
            "detection_service_error status=%d body=%s",
            resp.status_code,
            resp.text[:256],
        )
    except httpx.TimeoutException:
        logger.error("detection_service_timeout url=%s", request_url)
    except Exception as exc:
        logger.error("detection_service_exception err=%s", exc)
    return None


# ---------------------------------------------------------------------------
# AISR Runtime integration (preferred single decision endpoint)
# ---------------------------------------------------------------------------

async def evaluate_runtime(
    tenant_id: str,
    content: str,
    metadata: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Call AISR Runtime to get a single decision (allow|warn|block).

    Returns the runtime decision JSON or None on failure.
    """
    if not AISR_RUNTIME_URL:
        return None

    if content is None:
        content = ""

    client = _get_http_client()
    payload = {
        "tenant_id": tenant_id,
        "content": content[:MAX_BODY_SIZE],
        "metadata": metadata,
    }
    try:
        resp = await client.post(
            f"{AISR_RUNTIME_URL}/runtime/evaluate",
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 200:
            return resp.json()
        logger.warning("aisr_runtime_error status=%d body=%s", resp.status_code, resp.text[:256])
    except httpx.TimeoutException:
        logger.error("aisr_runtime_timeout")
    except Exception as exc:
        logger.error("aisr_runtime_exception err=%s", exc)
    return None


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------

async def emit_telemetry(entry: TrafficLogEntry) -> None:
    """Send a structured log entry to the SIEM/telemetry pipeline."""
    client = _get_http_client()
    try:
        await client.post(
            TELEMETRY_ENDPOINT,
            json=entry.to_dict(),
            headers={
                "x-api-key": TELEMETRY_API_KEY,
                "Content-Type": "application/json",
            },
        )
    except Exception as exc:
        # Telemetry failures must not block traffic.
        logger.debug("telemetry_emit_failed err=%s", exc)


async def resolve_tenant_mode(tenant_id: str) -> str:
    """Resolve runtime mode for a tenant with short-lived cache."""
    now = time.time()
    cached = _tenant_mode_cache.get(tenant_id)
    if cached and now < cached[1]:
        return cached[0]

    client = _get_http_client()
    mode = DEFAULT_PROXY_RUNTIME_MODE if DEFAULT_PROXY_RUNTIME_MODE in {"mitm", "envoy"} else "mitm"
    try:
        resp = await client.get(
            f"{POLICY_SERVICE_URL}/proxy-mode/{tenant_id}",
            headers={"x-api-key": POLICY_SECRET or ""},
        )
        if resp.status_code == 200:
            data = resp.json()
            resolved = str(data.get("mode", mode)).lower()
            if resolved in {"mitm", "envoy"}:
                mode = resolved
    except Exception as exc:
        logger.debug("tenant_mode_lookup_failed tenant=%s err=%s", tenant_id, exc)

    _tenant_mode_cache[tenant_id] = (mode, now + TENANT_MODE_CACHE_TTL_SECONDS)
    return mode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_host(url: str) -> str:
    """Extract hostname from a URL string."""
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _safe_decode_body(raw: Optional[bytes]) -> str:
    """Decode body bytes to string, truncating to MAX_BODY_SIZE."""
    if not raw:
        return ""
    try:
        return raw[:MAX_BODY_SIZE].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _get_request_id(flow: http.HTTPFlow) -> str:
    """Retrieve or assign a unique request ID for the flow."""
    if not hasattr(flow, "_aishields_request_id"):
        flow._aishields_request_id = str(uuid4())  # type: ignore[attr-defined]
    return flow._aishields_request_id  # type: ignore[attr-defined]


def _build_block_response(reason: str, request_id: str) -> http.Response:
    """Create a standardised 403 block response."""
    body = json.dumps({
        "error": "blocked_by_policy",
        "reason": reason,
        "request_id": request_id,
        "service": "aishields-proxy",
    }).encode("utf-8")
    return http.Response.make(
        403,
        body,
        {"Content-Type": "application/json", "X-AIShields-Request-ID": request_id},
    )


# ---------------------------------------------------------------------------
# mitmproxy Addon: TransparentProxyAddon
# ---------------------------------------------------------------------------

class TransparentProxyAddon:
    """Main mitmproxy addon that hooks into request/response lifecycle.

    Responsibilities:
    - Intercept every HTTP/HTTPS flow
    - Evaluate requests against the Policy Service
    - Scan request and response bodies via the Detection Service
    - Block or warn based on policy decisions
    - Emit telemetry for every inspected flow
    """

    def __init__(self) -> None:
        self._stats_lock = threading.Lock()
        self._stats: Dict[str, int] = {
            "total_requests": 0,
            "blocked": 0,
            "warned": 0,
            "allowed": 0,
            "errors": 0,
        }
        logger.info(
            "TransparentProxyAddon initialised mode=%s fail_open=%s",
            PROXY_MODE,
            FAIL_OPEN,
        )

    # ---- Statistics -------------------------------------------------------

    def _inc_stat(self, key: str) -> None:
        with self._stats_lock:
            self._stats[key] = self._stats.get(key, 0) + 1

    @property
    def stats(self) -> Dict[str, int]:
        with self._stats_lock:
            return dict(self._stats)

    # ---- mitmproxy hooks --------------------------------------------------

    def request(self, flow: http.HTTPFlow) -> None:
        """Synchronous request hook -- delegates to async pipeline."""
        self._inc_stat("total_requests")
        # Run async inspection in the mitmproxy event loop
        asyncio.ensure_future(self._inspect_request(flow))

    def response(self, flow: http.HTTPFlow) -> None:
        """Synchronous response hook -- delegates to async pipeline."""
        asyncio.ensure_future(self._inspect_response(flow))

    def error(self, flow: http.HTTPFlow) -> None:
        """Handle flow errors (e.g. connection resets)."""
        self._inc_stat("errors")
        request_id = _get_request_id(flow)
        logger.warning(
            "flow_error request_id=%s url=%s error=%s",
            request_id,
            flow.request.pretty_url if flow.request else "unknown",
            flow.error.msg if flow.error else "unknown",
        )

    # ---- Async inspection pipeline ----------------------------------------

    async def _inspect_request(self, flow: http.HTTPFlow) -> None:
        """Full request inspection pipeline.

        1. Extract metadata from the request.
        2. Evaluate against the Policy Service.
        3. Optionally scan the request body via the Detection Service.
        4. Block the request if a policy dictates.
        """
        request_id = _get_request_id(flow)
        start_ts = time.monotonic()

        url = flow.request.pretty_url
        method = flow.request.method
        host = flow.request.host
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
        content_type = flow.request.headers.get("content-type", "")
        body_text = _safe_decode_body(flow.request.get_content())
        tenant_id = flow.request.headers.get("x-tenant-id", TENANT_ID)
        tenant_mode = await resolve_tenant_mode(tenant_id)

        headers_dict = dict(flow.request.headers)

        logger.info(
            "inspect_request request_id=%s method=%s url=%s client=%s",
            request_id,
            method,
            url,
            client_ip,
        )

        # -- Step 1: Optional mode bypass -----------------------------------
        inspection = InspectionResult(request_id=request_id)
        if tenant_mode == "envoy":
            inspection.action = "allow"
            inspection.reason = "tenant_mode_envoy_bypass"
            inspection.latency_ms = (time.monotonic() - start_ts) * 1000.0
        else:
            # Preferred path: single AISR Runtime decision endpoint.
            runtime_result = None
            if body_text and len(body_text.strip()) > 0:
                runtime_result = await evaluate_runtime(
                    tenant_id=tenant_id,
                    content=body_text,
                    metadata={
                        "url": url,
                        "method": method,
                        "host": host,
                        "headers": headers_dict,
                        "client_ip": client_ip,
                        "content_type": content_type,
                        "direction": "request",
                    },
                )

            if runtime_result:
                # Runtime schema: decision=allow|block|redact
                decision = (runtime_result.get("decision") or "allow").lower()
                if decision == "block":
                    inspection.action = "block"
                elif decision in {"warn", "redact"}:
                    inspection.action = "warn"
                else:
                    inspection.action = "allow"

                reasons = runtime_result.get("reasons") or []
                inspection.reason = ",".join(reasons) if isinstance(reasons, list) else str(reasons)

                # Carry through risk metadata when present
                risk = runtime_result.get("risk") or {}
                try:
                    inspection.risk_score = float(risk.get("score", 0.0))
                except Exception:
                    inspection.risk_score = 0.0

                # Carry through findings/detections if runtime returns them
                evidence = runtime_result.get("evidence_snapshot")
                if evidence and isinstance(evidence, dict):
                    # Store as detections for telemetry visibility
                    inspection.detections = [{"type": "evidence_snapshot", "data": evidence}]
            else:
                # Legacy fallback path (policy + detection) if runtime unavailable.
                policy_result = await evaluate_policy(
                    tenant_id=tenant_id,
                    request_url=url,
                    method=method,
                    headers=headers_dict,
                    body_snippet=body_text[:2048],
                    client_ip=client_ip,
                )

                if policy_result:
                    action = policy_result.get("action", "allow")
                    inspection.action = action
                    inspection.reason = policy_result.get("reason", "")
                    inspection.policy_id = policy_result.get("policy_id")
                    inspection.policy_name = policy_result.get("policy_name")
                else:
                    if not FAIL_OPEN:
                        inspection.action = "block"
                        inspection.reason = "policy_service_unavailable_fail_closed"

                if body_text and len(body_text.strip()) > 0:
                    scan_result = await scan_content(
                        tenant_id=tenant_id,
                        content=body_text,
                        direction="request",
                        content_type=content_type,
                        request_url=url,
                    )
                    if scan_result:
                        inspection.detections = scan_result.get("detections", [])
                        inspection.risk_score = scan_result.get("risk_score", 0.0)
                        detection_action = scan_result.get("action")
                        if detection_action == "block":
                            inspection.action = "block"
                            inspection.reason = scan_result.get("reason", "detection_block")
                        elif detection_action == "warn" and inspection.action not in ("block",):
                            inspection.action = "warn"
                            inspection.reason = scan_result.get("reason", "detection_warn")

            inspection.latency_ms = (time.monotonic() - start_ts) * 1000.0

        # -- Step 3: Enforce action ------------------------------------------
        if inspection.action == "block":
            self._inc_stat("blocked")
            logger.warning(
                "request_blocked request_id=%s url=%s reason=%s policy=%s",
                request_id,
                url,
                inspection.reason,
                inspection.policy_name,
            )
            flow.response = _build_block_response(inspection.reason, request_id)
        elif inspection.action == "warn":
            self._inc_stat("warned")
            logger.info(
                "request_warned request_id=%s url=%s reason=%s",
                request_id,
                url,
                inspection.reason,
            )
            # Inject warning header but allow the request to proceed
            flow.request.headers["X-AIShields-Warning"] = inspection.reason
            flow.request.headers["X-AIShields-Request-ID"] = request_id
        else:
            self._inc_stat("allowed")

        # -- Step 4: Telemetry -----------------------------------------------
        # Store inspection result on the flow for use in the response hook
        flow._aishields_inspection = inspection  # type: ignore[attr-defined]

        log_entry = TrafficLogEntry(
            request_id=request_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            client_ip=client_ip,
            method=method,
            url=url,
            host=host,
            request_content_type=content_type,
            request_body_size=len(body_text),
            action=inspection.action,
            reason=inspection.reason,
            policy_id=inspection.policy_id,
            risk_score=inspection.risk_score,
            detections=inspection.detections,
            inspection_latency_ms=inspection.latency_ms,
            tenant_id=tenant_id,
            proxy_mode=PROXY_MODE,
        )
        await emit_telemetry(log_entry)

    async def _inspect_response(self, flow: http.HTTPFlow) -> None:
        """Response inspection pipeline.

        Scans response bodies for sensitive data leakage and emits telemetry
        with the complete request-response pair information.
        """
        request_id = _get_request_id(flow)
        if flow.response is None:
            return

        url = flow.request.pretty_url
        response_content_type = flow.response.headers.get("content-type", "")
        response_body = _safe_decode_body(flow.response.get_content())
        tenant_id = flow.request.headers.get("x-tenant-id", TENANT_ID)
        tenant_mode = await resolve_tenant_mode(tenant_id)

        # Inject request ID into the response for traceability
        flow.response.headers["X-AIShields-Request-ID"] = request_id

        # Scan response body for sensitive content / data leakage
        if tenant_mode != "envoy" and response_body and len(response_body.strip()) > 0:
            scan_result = await scan_content(
                tenant_id=tenant_id,
                content=response_body,
                direction="response",
                content_type=response_content_type,
                request_url=url,
            )
            if scan_result:
                detection_action = scan_result.get("action")
                if detection_action == "block":
                    logger.warning(
                        "response_blocked request_id=%s url=%s reason=%s",
                        request_id,
                        url,
                        scan_result.get("reason", "response_block"),
                    )
                    # Replace response with a block notice
                    flow.response = _build_block_response(
                        scan_result.get("reason", "response_content_blocked"),
                        request_id,
                    )
                    self._inc_stat("blocked")

        # Emit response-phase telemetry
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
        inspection: Optional[InspectionResult] = getattr(
            flow, "_aishields_inspection", None
        )

        log_entry = TrafficLogEntry(
            request_id=request_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            client_ip=client_ip,
            method=flow.request.method,
            url=url,
            host=flow.request.host,
            response_status=flow.response.status_code if flow.response else None,
            response_content_type=response_content_type,
            response_body_size=len(response_body) if response_body else 0,
            action=inspection.action if inspection else "allow",
            reason=inspection.reason if inspection else "",
            policy_id=inspection.policy_id if inspection else None,
            risk_score=inspection.risk_score if inspection else 0.0,
            detections=inspection.detections if inspection else [],
            inspection_latency_ms=inspection.latency_ms if inspection else 0.0,
            tenant_id=tenant_id,
            proxy_mode=PROXY_MODE,
        )
        await emit_telemetry(log_entry)


# ---------------------------------------------------------------------------
# Addon registration (mitmproxy picks this up automatically)
# ---------------------------------------------------------------------------
addons = [TransparentProxyAddon()]


# ---------------------------------------------------------------------------
# Management API (FastAPI) -- runs on a separate port for health/status
# ---------------------------------------------------------------------------
try:
    from fastapi import FastAPI

    management_app = FastAPI(
        title="AIShields Proxy Management API",
        version="1.0.0",
    )

    @management_app.get("/health")
    async def health():
        """Health check endpoint."""
        return {
            "status": "ok",
            "service": "aishields-transparent-proxy",
            "mode": PROXY_MODE,
            "version": "1.0.0",
        }

    @management_app.get("/stats")
    async def stats():
        """Return proxy traffic statistics."""
        addon = addons[0] if addons else None
        return {
            "stats": addon.stats if addon else {},
            "config": {
                "proxy_mode": PROXY_MODE,
                "fail_open": FAIL_OPEN,
                "tenant_id": TENANT_ID,
                "max_body_size": MAX_BODY_SIZE,
                "inspection_timeout": INSPECTION_TIMEOUT,
            },
        }

    @management_app.get("/config")
    async def get_config():
        """Return current proxy configuration (non-sensitive values)."""
        return {
            "proxy_mode": PROXY_MODE,
            "listen_host": PROXY_LISTEN_HOST,
            "listen_port": PROXY_LISTEN_PORT,
            "fail_open": FAIL_OPEN,
            "tenant_id": TENANT_ID,
            "max_body_size": MAX_BODY_SIZE,
            "inspection_timeout_s": INSPECTION_TIMEOUT,
            "policy_service_url": POLICY_SERVICE_URL,
            "detection_service_url": DETECTION_SERVICE_URL,
            "telemetry_endpoint": TELEMETRY_ENDPOINT,
        }

    @management_app.post("/reload")
    async def reload_config():
        """Trigger a soft configuration reload (re-reads env vars)."""
        # In a production deployment, this would signal the proxy to
        # re-read configuration files or a config store. For now, return
        # acknowledgement -- the proxy reads env vars at startup.
        logger.info("config_reload_requested")
        return {"status": "reload_acknowledged"}

except ImportError:
    # FastAPI not available -- management API disabled
    management_app = None  # type: ignore[assignment]
    logger.warning("FastAPI not installed; management API disabled")
