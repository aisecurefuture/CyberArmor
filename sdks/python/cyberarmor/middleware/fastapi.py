"""
CyberArmor FastAPI / Starlette Middleware
==========================================
Provides :class:`CyberArmorMiddleware`, an ASGI middleware that validates
AI agent identities on every incoming HTTP request by inspecting the
``X-Agent-Id`` and ``X-Agent-Token`` headers.

Requests that carry a valid agent identity pass through to the application.
Requests with missing or invalid credentials receive a ``403 Forbidden``
response before the application handler is invoked.

Usage::

    from fastapi import FastAPI
    from cyberarmor.middleware.fastapi import CyberArmorMiddleware

    app = FastAPI()
    app.add_middleware(CyberArmorMiddleware)

    # Or with a custom CyberArmor client:
    from cyberarmor import CyberArmorClient
    ca_client = CyberArmorClient()
    app.add_middleware(CyberArmorMiddleware, cyberarmor_client=ca_client)
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable, List, Optional, Sequence

import structlog

from cyberarmor.client import CyberArmorClient
from cyberarmor.config import CyberArmorConfig

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Header names
# ---------------------------------------------------------------------------

HEADER_AGENT_ID = "x-agent-id"
HEADER_AGENT_TOKEN = "x-agent-token"
HEADER_REQUEST_ID = "x-request-id"

# Paths that bypass identity validation (health checks, metrics, etc.)
DEFAULT_BYPASS_PATHS: List[str] = ["/health", "/healthz", "/ready", "/metrics"]


def _json_response(status_code: int, body: dict) -> tuple:
    """Return (status_line, headers, body_bytes) for a plain JSON ASGI response."""
    body_bytes = json.dumps(body).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body_bytes)).encode()),
    ]
    return status_code, headers, body_bytes


class CyberArmorMiddleware:
    """
    ASGI middleware for FastAPI / Starlette that validates AI agent identity
    tokens on every request.

    The middleware reads the ``X-Agent-Id`` and ``X-Agent-Token`` headers,
    then calls the CyberArmor identity service to validate the JWT or shared
    secret token.  On failure it short-circuits with ``403 Forbidden`` before
    the application handler runs.

    Args:
        app: The ASGI application to wrap.
        cyberarmor_client: Optional
            :class:`~cyberarmor.client.CyberArmorClient`.  Created from
            environment variables if omitted.
        bypass_paths: URL paths that skip identity validation (default:
            ``/health``, ``/healthz``, ``/ready``, ``/metrics``).
        require_agent_id: If ``True`` (default), requests without the
            ``X-Agent-Id`` header are immediately rejected.  Set to
            ``False`` to allow anonymous requests through (useful when only
            some endpoints are agent-facing).
        enforce: Override the enforcement mode.  When ``False`` the
            middleware logs violations but lets requests through.
    """

    def __init__(
        self,
        app: Any,
        *,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        bypass_paths: Optional[Sequence[str]] = None,
        require_agent_id: bool = True,
        enforce: Optional[bool] = None,
    ) -> None:
        self._app = app

        if cyberarmor_client is None:
            cyberarmor_client = CyberArmorClient()

        self._ca_client = cyberarmor_client
        self._config: CyberArmorConfig = cyberarmor_client.config
        self._bypass_paths: List[str] = list(
            bypass_paths if bypass_paths is not None else DEFAULT_BYPASS_PATHS
        )
        self._require_agent_id = require_agent_id

        # Enforcement mode: defer to config if not explicitly overridden
        if enforce is not None:
            self._enforce = enforce
        else:
            self._enforce = self._config.enforce_mode == "enforce"

        logger.info(
            "cyberarmor.fastapi.middleware_initialized",
            enforce=self._enforce,
            require_agent_id=require_agent_id,
            bypass_paths=self._bypass_paths,
        )

    # ------------------------------------------------------------------
    # ASGI interface
    # ------------------------------------------------------------------

    async def __call__(
        self,
        scope: dict,
        receive: Callable,
        send: Callable,
    ) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self._app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        # Bypass configured paths (health checks, etc.)
        if any(path.startswith(bp) for bp in self._bypass_paths):
            await self._app(scope, receive, send)
            return

        request_id = str(uuid.uuid4())
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }

        agent_id = headers.get(HEADER_AGENT_ID)
        agent_token = headers.get(HEADER_AGENT_TOKEN)
        incoming_request_id = headers.get(HEADER_REQUEST_ID, request_id)

        log = logger.bind(
            request_id=incoming_request_id,
            agent_id=agent_id,
            path=path,
        )

        # ---- Missing agent ID -------------------------------------------
        if not agent_id:
            if self._require_agent_id:
                log.warning("cyberarmor.fastapi.missing_agent_id")
                if self._enforce:
                    await self._send_error(
                        send,
                        status_code=403,
                        code="MISSING_AGENT_ID",
                        message="X-Agent-Id header is required.",
                        request_id=incoming_request_id,
                    )
                    return
            # Not required or not enforcing — pass through
            await self._app(scope, receive, send)
            return

        # ---- Validate token via identity service -------------------------
        start_ts = time.monotonic()
        try:
            valid = await self._ca_client.identity.validate_agent_token_async(
                agent_id=agent_id,
                token=agent_token or "",
            )
        except Exception as exc:
            log.error(
                "cyberarmor.fastapi.identity_check_failed",
                error=str(exc),
                duration_ms=int((time.monotonic() - start_ts) * 1000),
            )
            if self._enforce:
                await self._send_error(
                    send,
                    status_code=503,
                    code="IDENTITY_SERVICE_UNAVAILABLE",
                    message="Agent identity service is temporarily unavailable.",
                    request_id=incoming_request_id,
                )
                return
            # Fail-open when not enforcing
            await self._app(scope, receive, send)
            return

        validation_ms = int((time.monotonic() - start_ts) * 1000)

        if not valid:
            log.warning(
                "cyberarmor.fastapi.invalid_token",
                duration_ms=validation_ms,
            )
            if self._enforce:
                await self._send_error(
                    send,
                    status_code=403,
                    code="INVALID_AGENT_TOKEN",
                    message="Agent token is invalid or expired.",
                    request_id=incoming_request_id,
                )
                return

        log.info(
            "cyberarmor.fastapi.agent_verified",
            duration_ms=validation_ms,
        )

        # Inject validated agent_id into request scope for downstream use
        scope.setdefault("state", {})
        scope["state"]["cyberarmor_agent_id"] = agent_id
        scope["state"]["cyberarmor_request_id"] = incoming_request_id

        await self._app(scope, receive, send)

    # ------------------------------------------------------------------
    # Helper: send a JSON error response
    # ------------------------------------------------------------------

    async def _send_error(
        self,
        send: Callable,
        *,
        status_code: int,
        code: str,
        message: str,
        request_id: str,
    ) -> None:
        body = json.dumps(
            {
                "error": {
                    "code": code,
                    "message": message,
                    "request_id": request_id,
                }
            }
        ).encode("utf-8")

        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(body)).encode()],
                    [b"x-request-id", request_id.encode()],
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})
