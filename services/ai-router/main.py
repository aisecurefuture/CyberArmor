"""CyberArmor AI Provider Router.

Unified gateway to all AI providers with credential vault,
request normalization, cost tracking, and CyberArmor governance.
Port: 8009
"""

import logging
import os
import time
import base64
import hashlib
import hmac
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import Column, String, DateTime, Text, create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from connectors import CONNECTOR_REGISTRY

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("ai_router")

ROUTER_API_SECRET = os.getenv("ROUTER_API_SECRET", "change-me-router")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://cyberarmor:cyberarmor@postgres:5432/cyberarmor")
ROUTER_ENCRYPTION_KEY = os.getenv("ROUTER_ENCRYPTION_KEY", "change-me-router-master-key-32-bytes!!!")
ROUTER_PQC_SECRET_KEY_HEX = os.getenv("ROUTER_PQC_SECRET_KEY_HEX")
ROUTER_PQC_SECRET_KEY_B64 = os.getenv("ROUTER_PQC_SECRET_KEY_B64")
AUDIT_SERVICE_URL = os.getenv("AUDIT_SERVICE_URL", "http://audit:8011")
AUDIT_API_SECRET = os.getenv("AUDIT_API_SECRET", "change-me-audit")
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
    if _bad(ROUTER_API_SECRET):
        failing.append("ROUTER_API_SECRET")
    if _bad(ROUTER_ENCRYPTION_KEY):
        failing.append("ROUTER_ENCRYPTION_KEY")
    if _bad(AUDIT_API_SECRET):
        failing.append("AUDIT_API_SECRET")
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


def _enforce_internal_transport() -> None:
    if ENFORCE_MTLS and not str(AUDIT_SERVICE_URL).lower().startswith("https://"):
        raise RuntimeError(
            "Refusing startup: CYBERARMOR_ENFORCE_MTLS=true requires AUDIT_SERVICE_URL to use https://"
        )


def _internal_httpx_kwargs() -> Dict[str, Any]:
    if not ENFORCE_MTLS:
        return {}
    return {
        "verify": TLS_CA_FILE,
        "cert": (TLS_CERT_FILE, TLS_KEY_FILE),
    }


_enforce_internal_transport()

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ── Provider Model Routing Map ────────────────────────────────────────────────

PROVIDER_MODEL_MAP: Dict[str, str] = {
    # OpenAI
    "gpt-4o": "openai", "gpt-4o-mini": "openai",
    "o1": "openai", "o1-mini": "openai", "o3": "openai", "o3-mini": "openai",
    "gpt-4-turbo": "openai", "gpt-4": "openai", "gpt-3.5-turbo": "openai",
    # Anthropic
    "claude-opus-4": "anthropic", "claude-opus-4-5": "anthropic",
    "claude-sonnet-4-5": "anthropic", "claude-3-5-sonnet-20241022": "anthropic",
    "claude-haiku-4-5": "anthropic", "claude-3-5-haiku-20241022": "anthropic",
    "claude-3-opus-20240229": "anthropic", "claude-3-sonnet-20240229": "anthropic",
    # Google
    "gemini-2.0-flash": "google", "gemini-2.0-pro": "google",
    "gemini-1.5-pro": "google", "gemini-1.5-flash": "google",
    "gemini-pro": "google",
    # Amazon Bedrock
    "amazon.titan-text-express-v1": "amazon",
    "amazon.nova-pro-v1:0": "amazon",
    "amazon.nova-lite-v1:0": "amazon",
    "meta.llama3-70b-instruct-v1:0": "amazon",
    "anthropic.claude-3-5-sonnet-20241022-v2:0": "amazon",
    # Microsoft / Azure
    "phi-4": "microsoft", "phi-3.5-mini": "microsoft",
    # xAI
    "grok-3": "xai", "grok-3-mini": "xai", "grok-3-fast": "xai",
    "grok-2": "xai", "grok-2-vision-1212": "xai",
    # Meta
    "llama-3.3-70b-instruct": "meta", "llama-3.2-90b-vision-instruct": "meta",
    "llama-3.2-11b-vision-instruct": "meta", "llama-3.1-405b-instruct": "meta",
    # Perplexity
    "sonar-pro": "perplexity", "sonar": "perplexity",
    "sonar-reasoning": "perplexity", "sonar-reasoning-pro": "perplexity",
}

PROVIDER_BASE_URLS: Dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "google": "https://generativelanguage.googleapis.com/v1beta",
    "amazon": "https://bedrock-runtime.us-east-1.amazonaws.com",
    "microsoft": "https://api.cognitive.microsoft.com",
    "xai": "https://api.x.ai/v1",
    "meta": "https://api.together.xyz/v1",
    "perplexity": "https://api.perplexity.ai",
}

PROVIDER_DISPLAY_NAMES: Dict[str, str] = {
    "openai": "OpenAI", "anthropic": "Anthropic", "google": "Google Gemini",
    "amazon": "Amazon Bedrock", "microsoft": "Microsoft Azure OpenAI",
    "xai": "xAI Grok", "meta": "Meta LLaMA", "perplexity": "Perplexity",
}

COST_PER_1K_TOKENS: Dict[str, Dict[str, float]] = {
    "gpt-4o":            {"input": 0.0025, "output": 0.010},
    "gpt-4o-mini":       {"input": 0.00015, "output": 0.0006},
    "o1":                {"input": 0.015, "output": 0.060},
    "o3-mini":           {"input": 0.0011, "output": 0.0044},
    "claude-opus-4":     {"input": 0.015, "output": 0.075},
    "claude-sonnet-4-5": {"input": 0.003, "output": 0.015},
    "claude-haiku-4-5":  {"input": 0.00025, "output": 0.00125},
    "gemini-2.0-flash":  {"input": 0.000075, "output": 0.0003},
    "gemini-1.5-pro":    {"input": 0.00125, "output": 0.005},
    "grok-3":            {"input": 0.003, "output": 0.015},
    "sonar-pro":         {"input": 0.003, "output": 0.015},
}

class ProviderCredentialModel(Base):
    __tablename__ = "router_provider_credentials"
    tenant_id = Column(String(64), primary_key=True)
    provider_id = Column(String(64), primary_key=True)
    api_key_ciphertext = Column(Text, nullable=False)
    base_url = Column(String(512), nullable=True)
    region = Column(String(128), nullable=True)
    org_id = Column(String(255), nullable=True)
    deployment_name = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

# Metrics counters
_METRICS: Dict[str, float] = {
    "requests_total": 0, "cost_usd_total": 0.0,
}
_PROVIDER_METRICS: Dict[str, Dict[str, float]] = {}


# ── DB and Encryption ─────────────────────────────────────────────────────────

def wait_for_db(max_wait_s: int = 45):
    start = time.time()
    while True:
        try:
            with engine.connect() as conn:
                conn.exec_driver_sql("SELECT 1")
            return
        except Exception as exc:
            if time.time() - start > max_wait_s:
                raise RuntimeError(f"DB not ready: {exc}") from exc
            time.sleep(0.5)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _tenant_data_key(tenant_id: str) -> bytes:
    # Tenant-scoped DEK derivation from master key using HMAC-SHA256.
    master = ROUTER_ENCRYPTION_KEY.encode()
    if len(master) < 32:
        master = (master + b"0" * 32)[:32]
    return hmac.new(master, tenant_id.encode(), hashlib.sha256).digest()


def _encrypt_key(api_key: str, tenant_id: str, provider: str) -> str:
    key = _tenant_data_key(tenant_id)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    aad = f"{tenant_id}:{provider}".encode()
    ciphertext = aesgcm.encrypt(nonce, api_key.encode(), aad)
    return base64.b64encode(nonce + ciphertext).decode()


def _decrypt_key(encrypted: str, tenant_id: str, provider: str) -> str:
    raw = base64.b64decode(encrypted)
    nonce, ciphertext = raw[:12], raw[12:]
    key = _tenant_data_key(tenant_id)
    aesgcm = AESGCM(key)
    aad = f"{tenant_id}:{provider}".encode()
    return aesgcm.decrypt(nonce, ciphertext, aad).decode()


def _get_router_kem_secret() -> Optional[bytes]:
    """Load optional PQC transport KEM secret for encrypted admin API keys."""
    if ROUTER_PQC_SECRET_KEY_HEX:
        try:
            return bytes.fromhex(ROUTER_PQC_SECRET_KEY_HEX)
        except ValueError as exc:
            raise ValueError(f"Invalid ROUTER_PQC_SECRET_KEY_HEX: {exc}")

    if ROUTER_PQC_SECRET_KEY_B64:
        try:
            return base64.b64decode(ROUTER_PQC_SECRET_KEY_B64)
        except Exception as exc:
            raise ValueError(f"Invalid ROUTER_PQC_SECRET_KEY_B64: {exc}")

    return None


def _unwrap_provider_api_key(raw_api_key: str) -> str:
    """Support optional PQC-wrapped API keys in configure/rotate payloads."""
    if not raw_api_key:
        raise HTTPException(status_code=400, detail="api_key is required")
    if raw_api_key.startswith("PQC:"):
        secret = _get_router_kem_secret()
        if not secret:
            raise HTTPException(
                status_code=503,
                detail=(
                    "PQC API key transport is enabled for this request but secret key is unavailable"
                ),
            )
        try:
            from cyberarmor_core.crypto import PQCKeyTransport
            return PQCKeyTransport().decrypt_api_key(raw_api_key, secret)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid encrypted api_key: {exc}")
    return raw_api_key


# ── Auth ──────────────────────────────────────────────────────────────────────

def verify_api_key(api_key: str | None = Header(default=None, alias="x-api-key")):
    if not api_key or api_key != ROUTER_API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


# ── Pydantic Models ───────────────────────────────────────────────────────────

class UnifiedChatRequest(BaseModel):
    messages: List[Dict[str, Any]]
    model: str
    provider: Optional[str] = None
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    stream: bool = False
    agent_id: Optional[str] = None
    trace_id: Optional[str] = None
    tenant_id: str = "default"
    tools: Optional[List[Dict]] = None
    system: Optional[str] = None


class UnifiedChatResponse(BaseModel):
    id: str
    model: str
    provider: str
    choices: List[Dict[str, Any]]
    usage: Dict[str, int]
    cost_usd: float
    trace_id: Optional[str]
    latency_ms: int


class CompletionRequest(BaseModel):
    model: str
    prompt: str
    provider: Optional[str] = None
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    tenant_id: str = "default"
    agent_id: Optional[str] = None
    trace_id: Optional[str] = None


class EmbeddingsRequest(BaseModel):
    model: str
    input: Any
    provider: Optional[str] = None
    tenant_id: str = "default"
    agent_id: Optional[str] = None
    trace_id: Optional[str] = None


class ImagesGenerateRequest(BaseModel):
    model: str
    prompt: str
    size: Optional[str] = "1024x1024"
    n: Optional[int] = 1
    provider: Optional[str] = None
    tenant_id: str = "default"
    agent_id: Optional[str] = None
    trace_id: Optional[str] = None


class ProviderCredentialConfig(BaseModel):
    api_key: str
    base_url: Optional[str] = None
    region: Optional[str] = None
    org_id: Optional[str] = None
    deployment_name: Optional[str] = None


class ProviderHealth(BaseModel):
    provider_id: str
    display_name: str
    status: str
    latency_ms: int
    models: List[str]
    configured: bool


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="CyberArmor AI Provider Router",
    version="1.0.0",
    description="Unified AI Provider Gateway with credential vault and governance",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def on_startup():
    wait_for_db()
    Base.metadata.create_all(bind=engine)


# ── Core Routing Logic ────────────────────────────────────────────────────────

def _resolve_provider(model: str, explicit_provider: Optional[str]) -> str:
    if explicit_provider and explicit_provider in PROVIDER_BASE_URLS:
        return explicit_provider
    provider = PROVIDER_MODEL_MAP.get(model)
    if not provider:
        raise HTTPException(status_code=400, detail=f"Unknown model '{model}'. Specify provider explicitly.")
    return provider


def _get_credentials(db: Session, tenant_id: str, provider: str) -> Optional[ProviderCredentialModel]:
    return (
        db.query(ProviderCredentialModel)
        .filter(
            ProviderCredentialModel.tenant_id.in_([tenant_id, "default"]),
            ProviderCredentialModel.provider_id == provider,
        )
        .order_by(ProviderCredentialModel.tenant_id.desc())
        .first()
    )


def _build_connector(provider: str, base_url: str, api_key: str, config: Dict[str, Any]):
    connector_cls = CONNECTOR_REGISTRY.get(provider)
    if not connector_cls:
        raise HTTPException(status_code=400, detail=f"No connector available for provider '{provider}'")
    return connector_cls(base_url=base_url, api_key=api_key, config=config)


def _estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    pricing = COST_PER_1K_TOKENS.get(model, {"input": 0.001, "output": 0.002})
    return (prompt_tokens * pricing["input"] + completion_tokens * pricing["output"]) / 1000


def _update_metrics(provider: str, cost: float, latency_ms: int):
    _METRICS["requests_total"] += 1
    _METRICS["cost_usd_total"] += cost
    if provider not in _PROVIDER_METRICS:
        _PROVIDER_METRICS[provider] = {"requests": 0, "cost": 0.0, "latency_sum": 0.0}
    _PROVIDER_METRICS[provider]["requests"] += 1
    _PROVIDER_METRICS[provider]["cost"] += cost
    _PROVIDER_METRICS[provider]["latency_sum"] += latency_ms


async def _emit_audit_event(
    *,
    tenant_id: str,
    agent_id: Optional[str],
    trace_id: Optional[str],
    provider: str,
    model: str,
    latency_ms: int,
    cost_usd: float,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
):
    payload = {
        "trace_id": trace_id or f"trc_{uuid4().hex[:16]}",
        "tenant_id": tenant_id or "default",
        "agent_id": agent_id or "unknown-agent",
        "event_type": "ai_router_inference",
        "provider": provider,
        "model": model,
        "outcome": "success",
        "latency_ms": latency_ms,
        "cost_usd": cost_usd,
        "action": {
            "type": "llm_call",
            "prompt_tokens": int(prompt_tokens),
            "completion_tokens": int(completion_tokens),
        },
    }
    headers = {"x-api-key": AUDIT_API_SECRET, "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=3.0, **_internal_httpx_kwargs()) as client:
            resp = await client.post(f"{AUDIT_SERVICE_URL.rstrip('/')}/events", json=payload, headers=headers)
            if resp.status_code not in (200, 201):
                logger.warning("audit_emit_failed status=%s body=%s", resp.status_code, resp.text[:200])
    except Exception as exc:
        logger.warning("audit_emit_error err=%s", exc)


def _normalize_usage(data: Dict[str, Any]) -> Dict[str, int]:
    usage = data.get("usage", {}) if isinstance(data, dict) else {}
    prompt_tokens = int(usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0)
    completion_tokens = int(usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0)
    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
    }


async def _route_openai_compatible(
    base_url: str, api_key: str, request: UnifiedChatRequest, provider: str
) -> UnifiedChatResponse:
    """Route to any OpenAI-compatible endpoint."""
    start = time.time()
    payload: Dict[str, Any] = {
        "model": request.model,
        "messages": request.messages,
    }
    if request.max_tokens:
        payload["max_tokens"] = request.max_tokens
    if request.temperature is not None:
        payload["temperature"] = request.temperature
    if request.tools:
        payload["tools"] = request.tools

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "X-CyberArmor-Agent-Id": request.agent_id or "",
        "X-CyberArmor-Trace-Id": request.trace_id or str(uuid4()),
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(f"{base_url}/chat/completions", json=payload, headers=headers)

    latency_ms = int((time.time() - start) * 1000)

    if resp.status_code != 200:
        logger.error("Provider %s error %s: %s", provider, resp.status_code, resp.text[:500])
        raise HTTPException(status_code=resp.status_code, detail=f"Provider error: {resp.text[:200]}")

    data = resp.json()
    usage = data.get("usage", {})
    prompt_tokens = usage.get("prompt_tokens", 0)
    completion_tokens = usage.get("completion_tokens", 0)
    cost = _estimate_cost(request.model, prompt_tokens, completion_tokens)
    _update_metrics(provider, cost, latency_ms)

    return UnifiedChatResponse(
        id=data.get("id", f"ca_{uuid4().hex[:12]}"),
        model=data.get("model", request.model),
        provider=provider,
        choices=data.get("choices", []),
        usage={"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
               "total_tokens": prompt_tokens + completion_tokens},
        cost_usd=cost,
        trace_id=request.trace_id,
        latency_ms=latency_ms,
    )


async def _route_anthropic(api_key: str, request: UnifiedChatRequest) -> UnifiedChatResponse:
    """Route to Anthropic Messages API."""
    start = time.time()
    system_msg = request.system or ""
    messages = [m for m in request.messages if m.get("role") != "system"]
    for m in request.messages:
        if m.get("role") == "system":
            system_msg = m.get("content", "")

    payload: Dict[str, Any] = {
        "model": request.model,
        "messages": messages,
        "max_tokens": request.max_tokens or 1024,
    }
    if system_msg:
        payload["system"] = system_msg

    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
        "X-CyberArmor-Agent-Id": request.agent_id or "",
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers)

    latency_ms = int((time.time() - start) * 1000)
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"Anthropic error: {resp.text[:200]}")

    data = resp.json()
    usage = data.get("usage", {})
    prompt_tokens = usage.get("input_tokens", 0)
    completion_tokens = usage.get("output_tokens", 0)
    cost = _estimate_cost(request.model, prompt_tokens, completion_tokens)
    _update_metrics("anthropic", cost, latency_ms)

    content = data.get("content", [])
    text = content[0].get("text", "") if content else ""
    choices = [{"message": {"role": "assistant", "content": text}, "finish_reason": data.get("stop_reason", "stop")}]

    return UnifiedChatResponse(
        id=data.get("id", f"ca_{uuid4().hex[:12]}"),
        model=data.get("model", request.model),
        provider="anthropic",
        choices=choices,
        usage={"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
               "total_tokens": prompt_tokens + completion_tokens},
        cost_usd=cost,
        trace_id=request.trace_id,
        latency_ms=latency_ms,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/ai/chat/completions", response_model=UnifiedChatResponse)
async def chat_completions(
    request: UnifiedChatRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Unified chat completion endpoint — routes to the correct AI provider."""
    provider = _resolve_provider(request.model, request.provider)
    creds = _get_credentials(db, request.tenant_id, provider)

    if not creds:
        raise HTTPException(
            status_code=424,
            detail=f"No credentials configured for provider '{provider}'. "
                   f"POST /credentials/providers/{provider}/configure first.",
        )

    started = time.perf_counter()
    api_key = _decrypt_key(creds.api_key_ciphertext, creds.tenant_id, provider)
    base_url = creds.base_url or PROVIDER_BASE_URLS.get(provider, "")
    connector = _build_connector(
        provider=provider,
        base_url=base_url,
        api_key=api_key,
        config={
            "region": creds.region,
            "org_id": creds.org_id,
            "deployment_name": creds.deployment_name,
        },
    )
    data = await connector.chat_completions(
        {
            "model": request.model,
            "messages": request.messages,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "tools": request.tools,
            "system": request.system,
        }
    )
    latency_ms = int((time.perf_counter() - started) * 1000)
    usage = _normalize_usage(data)
    cost = _estimate_cost(request.model, usage["prompt_tokens"], usage["completion_tokens"])
    _update_metrics(provider, cost, latency_ms)
    await _emit_audit_event(
        tenant_id=request.tenant_id,
        agent_id=request.agent_id,
        trace_id=request.trace_id,
        provider=provider,
        model=data.get("model", request.model),
        latency_ms=latency_ms,
        cost_usd=cost,
        prompt_tokens=usage["prompt_tokens"],
        completion_tokens=usage["completion_tokens"],
    )
    return UnifiedChatResponse(
        id=data.get("id", f"ca_{uuid4().hex[:12]}"),
        model=data.get("model", request.model),
        provider=provider,
        choices=data.get("choices", []),
        usage=usage,
        cost_usd=cost,
        trace_id=request.trace_id,
        latency_ms=latency_ms,
    )


@app.post("/ai/messages", response_model=UnifiedChatResponse)
async def messages_anthropic_envelope(
    request: UnifiedChatRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Anthropic-style envelope — translated to unified response."""
    request.provider = "anthropic"
    creds = _get_credentials(db, request.tenant_id, "anthropic")
    if not creds:
        raise HTTPException(status_code=424, detail="Anthropic not configured")
    return await chat_completions(request=request, db=db, _=None)  # type: ignore[arg-type]


@app.post("/ai/completions")
async def completions(
    request: CompletionRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    provider = _resolve_provider(request.model, request.provider)
    creds = _get_credentials(db, request.tenant_id, provider)
    if not creds:
        raise HTTPException(status_code=424, detail=f"No credentials configured for provider '{provider}'")
    started = time.perf_counter()
    connector = _build_connector(
        provider=provider,
        base_url=creds.base_url or PROVIDER_BASE_URLS[provider],
        api_key=_decrypt_key(creds.api_key_ciphertext, creds.tenant_id, provider),
        config={},
    )
    data = await connector.completions(
        {
            "model": request.model,
            "prompt": request.prompt,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
    )
    latency_ms = int((time.perf_counter() - started) * 1000)
    usage = _normalize_usage(data)
    cost = _estimate_cost(request.model, usage["prompt_tokens"], usage["completion_tokens"])
    _update_metrics(provider, cost, latency_ms)
    await _emit_audit_event(
        tenant_id=request.tenant_id,
        agent_id=request.agent_id,
        trace_id=request.trace_id,
        provider=provider,
        model=data.get("model", request.model),
        latency_ms=latency_ms,
        cost_usd=cost,
        prompt_tokens=usage["prompt_tokens"],
        completion_tokens=usage["completion_tokens"],
    )
    return {
        "id": data.get("id", f"cmp_{uuid4().hex[:12]}"),
        "provider": provider,
        "model": data.get("model", request.model),
        "choices": data.get("choices", []),
        "usage": usage,
        "cost_usd": cost,
        "latency_ms": latency_ms,
        "trace_id": request.trace_id,
    }


@app.post("/ai/embeddings")
async def embeddings(
    request: EmbeddingsRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    provider = _resolve_provider(request.model, request.provider)
    creds = _get_credentials(db, request.tenant_id, provider)
    if not creds:
        raise HTTPException(status_code=424, detail=f"No credentials configured for provider '{provider}'")
    connector = _build_connector(
        provider=provider,
        base_url=creds.base_url or PROVIDER_BASE_URLS[provider],
        api_key=_decrypt_key(creds.api_key_ciphertext, creds.tenant_id, provider),
        config={},
    )
    data = await connector.embeddings({"model": request.model, "input": request.input})
    return {"provider": provider, **data}


@app.post("/ai/images/generate")
async def images_generate(
    request: ImagesGenerateRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    provider = _resolve_provider(request.model, request.provider)
    creds = _get_credentials(db, request.tenant_id, provider)
    if not creds:
        raise HTTPException(status_code=424, detail=f"No credentials configured for provider '{provider}'")
    connector = _build_connector(
        provider=provider,
        base_url=creds.base_url or PROVIDER_BASE_URLS[provider],
        api_key=_decrypt_key(creds.api_key_ciphertext, creds.tenant_id, provider),
        config={},
    )
    data = await connector.images_generate(
        {"model": request.model, "prompt": request.prompt, "size": request.size, "n": request.n}
    )
    return {"provider": provider, **data}


@app.get("/ai/models")
def list_models(_: None = Depends(verify_api_key)):
    """List all available models across providers."""
    by_provider: Dict[str, List[str]] = {}
    for model, provider in PROVIDER_MODEL_MAP.items():
        by_provider.setdefault(provider, []).append(model)
    models = []
    for provider, model_list in by_provider.items():
        for m in model_list:
            models.append({
                "id": m, "provider": provider,
                "display_name": PROVIDER_DISPLAY_NAMES.get(provider, provider),
                "object": "model",
            })
    return {"object": "list", "data": models}


@app.get("/ai/providers", response_model=List[ProviderHealth])
def list_providers(db: Session = Depends(get_db), _: None = Depends(verify_api_key)):
    """List configured providers with health status."""
    configured_provider_ids = {
        row[0]
        for row in db.query(ProviderCredentialModel.provider_id).distinct().all()
    }
    providers = []
    for pid, name in PROVIDER_DISPLAY_NAMES.items():
        configured = pid in configured_provider_ids
        models = [m for m, p in PROVIDER_MODEL_MAP.items() if p == pid]
        providers.append(ProviderHealth(
            provider_id=pid,
            display_name=name,
            status="configured" if configured else "unconfigured",
            latency_ms=0,
            models=models[:5],
            configured=configured,
        ))
    return providers


@app.post("/credentials/providers/{provider}/configure")
def configure_provider(
    provider: str,
    body: ProviderCredentialConfig,
    tenant_id: str = "default",
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    if provider not in PROVIDER_BASE_URLS:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")
    plain_api_key = _unwrap_provider_api_key(body.api_key)
    rec = (
        db.query(ProviderCredentialModel)
        .filter(
            ProviderCredentialModel.tenant_id == tenant_id,
            ProviderCredentialModel.provider_id == provider,
        )
        .first()
    )
    encrypted = _encrypt_key(plain_api_key, tenant_id, provider)
    if rec:
        rec.api_key_ciphertext = encrypted
        rec.base_url = body.base_url or PROVIDER_BASE_URLS[provider]
        rec.region = body.region
        rec.org_id = body.org_id
        rec.deployment_name = body.deployment_name
        rec.updated_at = datetime.now(timezone.utc)
    else:
        rec = ProviderCredentialModel(
            tenant_id=tenant_id,
            provider_id=provider,
            api_key_ciphertext=encrypted,
            base_url=body.base_url or PROVIDER_BASE_URLS[provider],
            region=body.region,
            org_id=body.org_id,
            deployment_name=body.deployment_name,
        )
        db.add(rec)
    db.commit()
    logger.info("Provider configured: provider=%s tenant=%s", provider, tenant_id)
    return {"status": "configured", "provider": provider, "tenant_id": tenant_id}


@app.get("/credentials/providers/{provider}/status")
def provider_status(
    provider: str,
    tenant_id: str = "default",
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    cred = _get_credentials(db, tenant_id, provider)
    return {
        "provider": provider,
        "configured": cred is not None,
        "status": "configured" if cred else "unconfigured",
        "base_url": (cred.base_url if cred else PROVIDER_BASE_URLS.get(provider, "")),
    }


@app.post("/credentials/providers/{provider}/rotate")
def rotate_provider_credentials(
    provider: str,
    body: ProviderCredentialConfig,
    tenant_id: str = "default",
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    rec = (
        db.query(ProviderCredentialModel)
        .filter(
            ProviderCredentialModel.tenant_id == tenant_id,
            ProviderCredentialModel.provider_id == provider,
        )
        .first()
    )
    if not rec:
        raise HTTPException(status_code=404, detail=f"Provider {provider} not configured")
    plain_api_key = _unwrap_provider_api_key(body.api_key)
    rec.api_key_ciphertext = _encrypt_key(plain_api_key, tenant_id, provider)
    rec.updated_at = datetime.now(timezone.utc)
    db.commit()
    logger.info("Credentials rotated: provider=%s tenant=%s", provider, tenant_id)
    return {"status": "rotated", "provider": provider}


@app.get("/health")
def health(db: Session = Depends(get_db)):
    providers_configured = db.query(ProviderCredentialModel.provider_id).distinct().count()
    return {"status": "ok", "service": "ai-router", "version": "1.0.0",
            "providers_configured": providers_configured}


@app.get("/ready")
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception:
        raise HTTPException(status_code=503, detail="Database not ready")


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    lines = [
        "# HELP cyberarmor_router_requests_total Total AI router requests",
        "# TYPE cyberarmor_router_requests_total counter",
        f'cyberarmor_router_requests_total {int(_METRICS["requests_total"])}',
        "# HELP cyberarmor_router_cost_usd_total Total AI cost in USD",
        "# TYPE cyberarmor_router_cost_usd_total counter",
        f'cyberarmor_router_cost_usd_total {_METRICS["cost_usd_total"]:.6f}',
    ]
    for provider, pm in _PROVIDER_METRICS.items():
        lines.append(f'cyberarmor_router_provider_requests_total{{provider="{provider}"}} {int(pm["requests"])}')
        lines.append(f'cyberarmor_router_provider_cost_usd_total{{provider="{provider}"}} {pm["cost"]:.6f}')
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain")
