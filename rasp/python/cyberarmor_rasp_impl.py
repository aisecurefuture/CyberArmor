"""CyberArmor RASP — Python Runtime Application Self-Protection.

Supports: WSGI, ASGI, requests, httpx, aiohttp monkey-patching.
Detects: AI/LLM API calls, prompt injection, sensitive data exfiltration.
"""

import functools
import json
import logging
import os
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("cyberarmor.rasp")


def _env(*keys: str, default: str = "") -> str:
    for key in keys:
        value = os.getenv(key)
        if value:
            return value
    return default

# ── Configuration ─────────────────────────────────────────
class RASPConfig:
    control_plane_url: str = _env("CYBERARMOR_URL", default="http://localhost:8000")
    api_key: str = _env("CYBERARMOR_API_KEY", default="")
    tenant_id: str = _env("CYBERARMOR_TENANT", default="default")
    mode: str = _env("CYBERARMOR_MODE", default="monitor")  # monitor | block
    dlp_enabled: bool = True
    prompt_injection_enabled: bool = True

config = RASPConfig()

# ── AI Endpoint Detection ─────────────────────────────────
AI_DOMAINS = {
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "api.cohere.ai", "api.mistral.ai", "api-inference.huggingface.co",
    "api.together.xyz", "api.replicate.com", "api.groq.com",
}
AI_AZURE_PATTERN = re.compile(r"\.openai\.azure\.com|\.cognitiveservices\.azure\.com")

def is_ai_endpoint(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return host in AI_DOMAINS or bool(AI_AZURE_PATTERN.search(host))
    except Exception:
        return False

# ── Prompt Injection Detection ────────────────────────────
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an|in)", re.I),
    re.compile(r"system\s*:\s*you\s+are", re.I),
    re.compile(r"<\s*(system|prompt|instruction)\s*>", re.I),
    re.compile(r"jailbreak|DAN\s+mode|bypass\s+filter", re.I),
    re.compile(r"forget\s+(everything|all|your)", re.I),
    re.compile(r"do\s+not\s+follow\s+(any|your)", re.I),
]

def detect_prompt_injection(text: str) -> Optional[str]:
    for p in PROMPT_INJECTION_PATTERNS:
        if p.search(text):
            return p.pattern
    return None

# ── DLP Patterns ──────────────────────────────────────────
DLP_PATTERNS = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b")),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}")),
    ("private_key", re.compile(r"-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+")),
]

def scan_dlp(text: str) -> List[str]:
    return [name for name, pat in DLP_PATTERNS if pat.search(text)]

# ── Telemetry ─────────────────────────────────────────────
_event_buffer: List[Dict] = []
_buffer_lock = threading.Lock()

def _record_event(event_type: str, url: str, detail: str = ""):
    evt = {"ts": time.time(), "type": event_type, "url": url, "detail": detail[:200], "tenant": config.tenant_id}
    with _buffer_lock:
        _event_buffer.append(evt)
        if len(_event_buffer) >= 50:
            batch = list(_event_buffer)
            _event_buffer.clear()
            threading.Thread(target=_flush, args=(batch,), daemon=True).start()

def _flush(batch):
    try:
        import httpx
        httpx.post(f"{config.control_plane_url}/telemetry/ingest",
                    json=batch, headers={"x-api-key": config.api_key}, timeout=5)
    except Exception:
        pass

# ── Core Inspection ───────────────────────────────────────
class InspectionResult:
    def __init__(self, allowed=True, reason="", event_type=""):
        self.allowed = allowed
        self.reason = reason
        self.event_type = event_type

def inspect_request(url: str, body: str = "") -> InspectionResult:
    """Inspect an outbound request to an AI service."""
    if not is_ai_endpoint(url):
        return InspectionResult()

    _record_event("ai_request", url)

    if config.prompt_injection_enabled and body:
        pattern = detect_prompt_injection(body)
        if pattern:
            _record_event("prompt_injection", url, pattern)
            if config.mode == "block":
                return InspectionResult(False, f"Prompt injection: {pattern}", "prompt_injection")

    if config.dlp_enabled and body:
        findings = scan_dlp(body)
        if findings:
            _record_event("sensitive_data", url, ",".join(findings))
            if config.mode == "block":
                return InspectionResult(False, f"Sensitive data: {','.join(findings)}", "dlp")

    return InspectionResult()

# ── WSGI Middleware ────────────────────────────────────────
class CyberArmorWSGI:
    """WSGI middleware for AI traffic inspection."""
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "")
        path = environ.get("PATH_INFO", "")
        host = environ.get("HTTP_HOST", "")
        url = f"https://{host}{path}"

        if method == "POST" and is_ai_endpoint(url):
            body = environ["wsgi.input"].read()
            environ["wsgi.input"] = __import__("io").BytesIO(body)
            result = inspect_request(url, body.decode("utf-8", errors="ignore"))
            if not result.allowed:
                start_response("403 Forbidden", [("Content-Type", "application/json")])
                return [json.dumps({"error": result.reason, "policy": "cyberarmor-rasp"}).encode()]

        return self.app(environ, start_response)

# ── ASGI Middleware ────────────────────────────────────────
class CyberArmorASGI:
    """ASGI middleware for AI traffic inspection."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        path = scope.get("path", "")
        headers = dict(scope.get("headers", []))
        host = headers.get(b"host", b"").decode()
        url = f"https://{host}{path}"

        if method == "POST" and is_ai_endpoint(url):
            body_parts = []
            async def receive_wrapper():
                msg = await receive()
                if msg["type"] == "http.request":
                    body_parts.append(msg.get("body", b""))
                return msg

            msg = await receive_wrapper()
            body = b"".join(body_parts).decode("utf-8", errors="ignore")
            result = inspect_request(url, body)
            if not result.allowed:
                await send({"type": "http.response.start", "status": 403, "headers": [[b"content-type", b"application/json"]]})
                await send({"type": "http.response.body", "body": json.dumps({"error": result.reason}).encode()})
                return

            # Replay body
            async def replayed_receive():
                return msg
            await self.app(scope, replayed_receive, send)
        else:
            await self.app(scope, receive, send)

# ── Monkey-Patching (requests, httpx) ─────────────────────
_patched = False

def patch():
    """Monkey-patch popular HTTP libraries to intercept AI API calls."""
    global _patched
    if _patched:
        return
    _patched = True

    # Patch requests
    try:
        import requests
        _orig_request = requests.Session.request
        @functools.wraps(_orig_request)
        def patched_request(self, method, url, **kwargs):
            if method.upper() == "POST":
                body = kwargs.get("json") or kwargs.get("data") or ""
                if isinstance(body, dict):
                    body = json.dumps(body)
                elif isinstance(body, bytes):
                    body = body.decode("utf-8", errors="ignore")
                result = inspect_request(str(url), str(body))
                if not result.allowed:
                    raise PermissionError(f"CyberArmor RASP blocked: {result.reason}")
            return _orig_request(self, method, url, **kwargs)
        requests.Session.request = patched_request
        logger.info("CyberArmor RASP: patched requests.Session")
    except ImportError:
        pass

    # Patch httpx
    try:
        import httpx
        _orig_send = httpx.Client.send
        @functools.wraps(_orig_send)
        def patched_send(self, request, **kwargs):
            if request.method == "POST":
                body = request.content.decode("utf-8", errors="ignore") if request.content else ""
                result = inspect_request(str(request.url), body)
                if not result.allowed:
                    raise PermissionError(f"CyberArmor RASP blocked: {result.reason}")
            return _orig_send(self, request, **kwargs)
        httpx.Client.send = patched_send
        logger.info("CyberArmor RASP: patched httpx.Client")
    except ImportError:
        pass

# ── Decorator API ─────────────────────────────────────────
def protect(func):
    """Decorator to protect a function that makes AI API calls."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        patch()
        return func(*args, **kwargs)
    return wrapper

# ── Auto-init ─────────────────────────────────────────────
def init(**kwargs):
    """Initialize CyberArmor RASP with custom configuration."""
    for k, v in kwargs.items():
        if hasattr(config, k):
            setattr(config, k, v)
    patch()
    logger.info("CyberArmor RASP initialized (mode=%s)", config.mode)


# Canonical class aliases for CyberArmor naming.
CyberArmorWSGI = CyberArmorWSGI
CyberArmorASGI = CyberArmorASGI
