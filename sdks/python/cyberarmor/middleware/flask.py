"""
CyberArmor Flask Middleware
============================
Provides :func:`cyberarmor_flask`, a function that registers a
``before_request`` hook on a Flask application to validate AI agent identity
tokens (``X-Agent-Id`` and ``X-Agent-Token`` headers) on every request.

Usage::

    from flask import Flask
    from cyberarmor.middleware.flask import cyberarmor_flask

    app = Flask(__name__)
    cyberarmor_flask(app)

    # Or with a custom CyberArmor client:
    from cyberarmor import CyberArmorClient
    ca_client = CyberArmorClient()
    cyberarmor_flask(app, client=ca_client)
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
# Header constants
# ---------------------------------------------------------------------------

HEADER_AGENT_ID = "X-Agent-Id"
HEADER_AGENT_TOKEN = "X-Agent-Token"
HEADER_REQUEST_ID = "X-Request-Id"

DEFAULT_BYPASS_PATHS: List[str] = ["/health", "/healthz", "/ready", "/metrics"]


def _json_error(status_code: int, code: str, message: str, request_id: str) -> Any:
    """
    Return a Flask ``Response`` object with a JSON error body.

    Defers Flask import so that Flask is an optional dependency.
    """
    try:
        from flask import Response  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "Flask is required for cyberarmor_flask. "
            "Install it with: pip install flask"
        ) from exc

    body = json.dumps(
        {
            "error": {
                "code": code,
                "message": message,
                "request_id": request_id,
            }
        }
    )
    return Response(
        response=body,
        status=status_code,
        mimetype="application/json",
        headers={HEADER_REQUEST_ID: request_id},
    )


def cyberarmor_flask(
    app: Any,
    client: Optional[CyberArmorClient] = None,
    *,
    bypass_paths: Optional[Sequence[str]] = None,
    require_agent_id: bool = True,
    enforce: Optional[bool] = None,
) -> None:
    """
    Register a CyberArmor ``before_request`` hook on a Flask application.

    The hook validates ``X-Agent-Id`` and ``X-Agent-Token`` headers on every
    incoming request.  On failure it returns ``403 Forbidden`` before the
    view function is called.

    Args:
        app: A Flask :class:`flask.Flask` application instance.
        client: Optional :class:`~cyberarmor.client.CyberArmorClient`.
            Created from environment variables if omitted.
        bypass_paths: URL prefixes that skip agent validation.
        require_agent_id: If ``True`` (default), requests without
            ``X-Agent-Id`` are rejected.
        enforce: Override enforcement mode.  When ``False``, violations are
            logged but not blocked (observe-only).
    """
    try:
        from flask import g, request  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "Flask is required for cyberarmor_flask. "
            "Install it with: pip install flask"
        ) from exc

    if client is None:
        client = CyberArmorClient()

    config: CyberArmorConfig = client.config
    _bypass: List[str] = list(
        bypass_paths if bypass_paths is not None else DEFAULT_BYPASS_PATHS
    )

    # Resolve enforce mode
    if enforce is not None:
        _enforce = enforce
    else:
        _enforce = config.enforce_mode == "enforce"

    logger.info(
        "cyberarmor.flask.registered",
        enforce=_enforce,
        require_agent_id=require_agent_id,
        bypass_paths=_bypass,
    )

    @app.before_request
    def _cyberarmor_before_request() -> Optional[Any]:
        """
        Before-request hook: validate agent identity credentials.

        Returns ``None`` to continue to the view function, or a Flask
        Response object to abort early with an error.
        """
        path: str = request.path

        # ---- Bypass paths ------------------------------------------------
        if any(path.startswith(bp) for bp in _bypass):
            return None

        # ---- Generate / read request ID ----------------------------------
        incoming_request_id = request.headers.get(HEADER_REQUEST_ID) or str(uuid.uuid4())
        g.cyberarmor_request_id = incoming_request_id

        agent_id: Optional[str] = request.headers.get(HEADER_AGENT_ID)
        agent_token: Optional[str] = request.headers.get(HEADER_AGENT_TOKEN)

        log = logger.bind(
            request_id=incoming_request_id,
            agent_id=agent_id,
            path=path,
            method=request.method,
        )

        # ---- Missing agent ID -------------------------------------------
        if not agent_id:
            if require_agent_id:
                log.warning("cyberarmor.flask.missing_agent_id")
                if _enforce:
                    return _json_error(
                        403,
                        "MISSING_AGENT_ID",
                        "X-Agent-Id header is required.",
                        incoming_request_id,
                    )
            return None

        # ---- Validate token via identity service -------------------------
        start_ts = time.monotonic()
        try:
            valid = client.identity.validate_agent_token(
                agent_id=agent_id,
                token=agent_token or "",
            )
        except Exception as exc:
            log.error(
                "cyberarmor.flask.identity_check_failed",
                error=str(exc),
                duration_ms=int((time.monotonic() - start_ts) * 1000),
            )
            if _enforce and not config.fail_open:
                return _json_error(
                    503,
                    "IDENTITY_SERVICE_UNAVAILABLE",
                    "Agent identity service is temporarily unavailable.",
                    incoming_request_id,
                )
            return None

        validation_ms = int((time.monotonic() - start_ts) * 1000)

        if not valid:
            log.warning(
                "cyberarmor.flask.invalid_token",
                duration_ms=validation_ms,
            )
            if _enforce:
                return _json_error(
                    403,
                    "INVALID_AGENT_TOKEN",
                    "Agent token is invalid or expired.",
                    incoming_request_id,
                )

        log.info("cyberarmor.flask.agent_verified", duration_ms=validation_ms)

        # Store validated identity in Flask's request context
        g.cyberarmor_agent_id = agent_id
        return None  # Continue to view function


class CyberArmorFlaskExtension:
    """
    Flask extension object for use with the application factory pattern.

    Example::

        from cyberarmor.middleware.flask import CyberArmorFlaskExtension

        ca = CyberArmorFlaskExtension()

        def create_app():
            app = Flask(__name__)
            ca.init_app(app)
            return app
    """

    def __init__(self) -> None:
        self._client: Optional[CyberArmorClient] = None

    def init_app(
        self,
        app: Any,
        *,
        client: Optional[CyberArmorClient] = None,
        bypass_paths: Optional[Sequence[str]] = None,
        require_agent_id: bool = True,
        enforce: Optional[bool] = None,
    ) -> None:
        """
        Initialise the extension with a Flask app.

        All keyword arguments are forwarded to :func:`cyberarmor_flask`.
        """
        if client is not None:
            self._client = client

        cyberarmor_flask(
            app,
            client=self._client,
            bypass_paths=bypass_paths,
            require_agent_id=require_agent_id,
            enforce=enforce,
        )
