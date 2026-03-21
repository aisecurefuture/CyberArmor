"""
CyberArmor Django Middleware
=============================
Provides :class:`CyberArmorMiddleware`, a Django middleware class that
validates AI agent identity tokens (``X-Agent-Id`` / ``X-Agent-Token``
headers) on every HTTP request using Django's new-style ``get_response``
middleware pattern.

Installation
------------
Add to ``settings.py``::

    MIDDLEWARE = [
        # ... other middleware ...
        "cyberarmor.middleware.django.CyberArmorMiddleware",
    ]

Configuration
-------------
The middleware reads CyberArmor settings from ``settings.py`` if present::

    CYBERARMOR = {
        "client": None,                    # CyberArmorClient instance or None
        "bypass_paths": ["/health/"],      # Paths to skip validation
        "require_agent_id": True,          # Reject requests without X-Agent-Id
        "enforce": True,                   # Block on failure (False = log-only)
    }

All settings fall back to environment variables (``CYBERARMOR_URL``,
``CYBERARMOR_ENFORCE_MODE``, etc.) when not specified in ``settings.py``.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable, List, Optional, Sequence

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Header constants
# ---------------------------------------------------------------------------

HEADER_AGENT_ID = "HTTP_X_AGENT_ID"       # Django META key
HEADER_AGENT_TOKEN = "HTTP_X_AGENT_TOKEN"
HEADER_REQUEST_ID = "HTTP_X_REQUEST_ID"

DEFAULT_BYPASS_PATHS: List[str] = ["/health/", "/healthz/", "/ready/", "/metrics/"]


def _json_403(code: str, message: str, request_id: str) -> Any:
    """Return a Django HttpResponse with a JSON 403 body."""
    try:
        from django.http import HttpResponse  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "Django is required for CyberArmorMiddleware. "
            "Install it with: pip install django"
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
    response = HttpResponse(body, content_type="application/json", status=403)
    response["X-Request-Id"] = request_id
    return response


def _json_503(code: str, message: str, request_id: str) -> Any:
    """Return a Django HttpResponse with a JSON 503 body."""
    try:
        from django.http import HttpResponse  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "Django is required for CyberArmorMiddleware. "
            "Install it with: pip install django"
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
    response = HttpResponse(body, content_type="application/json", status=503)
    response["X-Request-Id"] = request_id
    return response


def _load_django_settings() -> dict:
    """
    Read optional ``CYBERARMOR`` dict from Django settings without crashing
    if Django is not configured.
    """
    try:
        from django.conf import settings  # type: ignore[import]
        return getattr(settings, "CYBERARMOR", {}) or {}
    except Exception:
        return {}


class CyberArmorMiddleware:
    """
    Django new-style middleware that validates AI agent identity tokens.

    Designed for the ``get_response`` middleware pattern introduced in
    Django 1.10+.

    The middleware checks ``X-Agent-Id`` and ``X-Agent-Token`` on every
    request.  Requests that fail validation receive a ``403 Forbidden``
    JSON response before the view is called.

    Configuration can be supplied via the ``CYBERARMOR`` dict in
    ``settings.py`` or through constructor arguments (useful for testing).

    Args:
        get_response: The next middleware or view callable (provided by
            Django's middleware machinery).
        cyberarmor_client: Optional
            :class:`~cyberarmor.client.CyberArmorClient`.
        bypass_paths: URL path prefixes to skip (default: health endpoints).
        require_agent_id: Reject requests with no ``X-Agent-Id`` header.
        enforce: Block on failure.  ``False`` enables observe-only mode.
    """

    def __init__(
        self,
        get_response: Callable,
        *,
        cyberarmor_client: Optional[Any] = None,
        bypass_paths: Optional[Sequence[str]] = None,
        require_agent_id: Optional[bool] = None,
        enforce: Optional[bool] = None,
    ) -> None:
        self._get_response = get_response

        # ---- Load Django settings (lowest priority) ----------------------
        django_cfg = _load_django_settings()

        # ---- Resolve CyberArmor client -----------------------------------
        if cyberarmor_client is None:
            cyberarmor_client = django_cfg.get("client")
        if cyberarmor_client is None:
            from cyberarmor.client import CyberArmorClient  # noqa: F401
            cyberarmor_client = CyberArmorClient()

        self._ca_client = cyberarmor_client
        self._config = cyberarmor_client.config

        # ---- Bypass paths -----------------------------------------------
        if bypass_paths is not None:
            self._bypass_paths: List[str] = list(bypass_paths)
        else:
            self._bypass_paths = list(
                django_cfg.get("bypass_paths", DEFAULT_BYPASS_PATHS)
            )

        # ---- Require agent ID -------------------------------------------
        if require_agent_id is not None:
            self._require_agent_id = require_agent_id
        else:
            self._require_agent_id = django_cfg.get("require_agent_id", True)

        # ---- Enforcement mode -------------------------------------------
        if enforce is not None:
            self._enforce = enforce
        else:
            if "enforce" in django_cfg:
                self._enforce = bool(django_cfg["enforce"])
            else:
                self._enforce = self._config.enforce_mode == "enforce"

        logger.info(
            "cyberarmor.django.middleware_initialized",
            enforce=self._enforce,
            require_agent_id=self._require_agent_id,
            bypass_paths=self._bypass_paths,
        )

    # ------------------------------------------------------------------
    # Django middleware interface
    # ------------------------------------------------------------------

    def __call__(self, request: Any) -> Any:
        """
        Process the request.

        Returns an error response (403 / 503) if agent validation fails and
        enforce mode is enabled.  Otherwise forwards to the next middleware
        or view.
        """
        path: str = getattr(request, "path", "/")

        # ---- Bypass configured paths ------------------------------------
        if any(path.startswith(bp) for bp in self._bypass_paths):
            return self._get_response(request)

        # ---- Extract headers from Django META dict ----------------------
        meta = getattr(request, "META", {})
        agent_id: Optional[str] = meta.get(HEADER_AGENT_ID)
        agent_token: Optional[str] = meta.get(HEADER_AGENT_TOKEN)
        incoming_request_id: str = meta.get(HEADER_REQUEST_ID) or str(uuid.uuid4())

        log = logger.bind(
            request_id=incoming_request_id,
            agent_id=agent_id,
            path=path,
            method=getattr(request, "method", "UNKNOWN"),
        )

        # Store request ID on request object for downstream access
        request.cyberarmor_request_id = incoming_request_id

        # ---- Missing agent ID -------------------------------------------
        if not agent_id:
            if self._require_agent_id:
                log.warning("cyberarmor.django.missing_agent_id")
                if self._enforce:
                    return _json_403(
                        "MISSING_AGENT_ID",
                        "X-Agent-Id header is required.",
                        incoming_request_id,
                    )
            return self._get_response(request)

        # ---- Validate token via identity service ------------------------
        start_ts = time.monotonic()
        try:
            valid = self._ca_client.identity.validate_agent_token(
                agent_id=agent_id,
                token=agent_token or "",
            )
        except Exception as exc:
            log.error(
                "cyberarmor.django.identity_check_failed",
                error=str(exc),
                duration_ms=int((time.monotonic() - start_ts) * 1000),
            )
            if self._enforce and not self._config.fail_open:
                return _json_503(
                    "IDENTITY_SERVICE_UNAVAILABLE",
                    "Agent identity service is temporarily unavailable.",
                    incoming_request_id,
                )
            return self._get_response(request)

        validation_ms = int((time.monotonic() - start_ts) * 1000)

        if not valid:
            log.warning(
                "cyberarmor.django.invalid_token",
                duration_ms=validation_ms,
            )
            if self._enforce:
                return _json_403(
                    "INVALID_AGENT_TOKEN",
                    "Agent token is invalid or expired.",
                    incoming_request_id,
                )

        log.info("cyberarmor.django.agent_verified", duration_ms=validation_ms)

        # Attach validated identity to the request object
        request.cyberarmor_agent_id = agent_id

        return self._get_response(request)

    # ------------------------------------------------------------------
    # process_view hook (Django-style, optional)
    # ------------------------------------------------------------------

    def process_view(
        self,
        request: Any,
        view_func: Callable,
        view_args: tuple,
        view_kwargs: dict,
    ) -> Optional[Any]:
        """
        Optional Django ``process_view`` hook.

        Called immediately before the view function is invoked.  Currently
        used only for debug logging; returns ``None`` to continue normally.
        """
        agent_id = getattr(request, "cyberarmor_agent_id", None)
        logger.debug(
            "cyberarmor.django.process_view",
            view=getattr(view_func, "__name__", str(view_func)),
            agent_id=agent_id,
            path=getattr(request, "path", "/"),
        )
        return None

    # ------------------------------------------------------------------
    # process_exception hook
    # ------------------------------------------------------------------

    def process_exception(
        self,
        request: Any,
        exception: Exception,
    ) -> Optional[Any]:
        """
        Optional Django ``process_exception`` hook.

        Logs unhandled exceptions with their associated agent ID so that
        security incidents can be correlated to a specific agent.
        """
        agent_id = getattr(request, "cyberarmor_agent_id", "anonymous")
        logger.error(
            "cyberarmor.django.unhandled_exception",
            agent_id=agent_id,
            path=getattr(request, "path", "/"),
            exception_type=type(exception).__name__,
            error=str(exception),
        )
        return None  # Allow Django's default exception handling
