"""CyberArmor SDK configuration.

Environment variable prefix: CYBERARMOR_
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional


def _env(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Read an environment variable with an optional default.
    """
    value = os.environ.get(key)
    if value is not None:
        return value
    return default


def _env_int(key: str, default: int = 0) -> int:
    raw = _env(key, str(default))
    try:
        return int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _env_bool(key: str, default: bool = False) -> bool:
    raw = _env(key, "true" if default else "false")
    return (raw or "").lower() in ("1", "true", "yes", "on")


def _env_list(key: str, default: Optional[List[str]] = None) -> List[str]:
    raw = _env(key)
    if raw:
        return [item.strip() for item in raw.split(",") if item.strip()]
    return default or []


@dataclass
class CyberArmorConfig:
    """
    Full SDK configuration.

    All fields have sensible defaults and can be overridden via environment
    variables or by passing keyword arguments to the constructor.

    Environment variable mapping
    ----------------------------
    api_key              -> CYBERARMOR_API_KEY
    api_url              -> CYBERARMOR_API_URL
    tenant_id            -> CYBERARMOR_TENANT_ID
    agent_id             -> CYBERARMOR_AGENT_ID
    environment          -> CYBERARMOR_ENVIRONMENT
    timeout_seconds      -> CYBERARMOR_TIMEOUT_SECONDS
    max_retries          -> CYBERARMOR_MAX_RETRIES
    audit_enabled        -> CYBERARMOR_AUDIT_ENABLED
    audit_batch_size     -> CYBERARMOR_AUDIT_BATCH_SIZE
    audit_flush_interval -> CYBERARMOR_AUDIT_FLUSH_INTERVAL
    dlp_enabled          -> CYBERARMOR_DLP_ENABLED
    injection_detection  -> CYBERARMOR_INJECTION_DETECTION
    local_policy_path    -> CYBERARMOR_LOCAL_POLICY_PATH
    signing_key          -> CYBERARMOR_SIGNING_KEY
    verify_ssl           -> CYBERARMOR_VERIFY_SSL
    log_level            -> CYBERARMOR_LOG_LEVEL
    allowed_models       -> CYBERARMOR_ALLOWED_MODELS     (comma-separated)
    blocked_models       -> CYBERARMOR_BLOCKED_MODELS     (comma-separated)
    """

    # Core authentication
    api_key: Optional[str] = None
    api_url: str = "https://api.cyberarmor.ai/v1"
    tenant_id: Optional[str] = None
    agent_id: Optional[str] = None

    # Runtime environment tag
    environment: str = "production"

    # HTTP client settings
    timeout_seconds: float = 10.0
    max_retries: int = 3

    # Audit / event pipeline
    audit_enabled: bool = True
    audit_batch_size: int = 50
    audit_flush_interval: float = 5.0   # seconds

    # In-process security features
    dlp_enabled: bool = True
    injection_detection: bool = True

    # Optional path to a local policy JSON file (offline mode)
    local_policy_path: Optional[str] = None

    # Event signing key (base64-encoded Ed25519 private key or HMAC secret)
    signing_key: Optional[str] = None

    # TLS verification
    verify_ssl: bool = True

    # Logging
    log_level: str = "WARNING"

    # Model allow/block lists (empty = unrestricted)
    allowed_models: List[str] = field(default_factory=list)
    blocked_models: List[str] = field(default_factory=list)

    # Token cache TTL (seconds)
    token_ttl: int = 3600

    # Maximum delegation chain depth (0 = unlimited)
    max_delegation_depth: int = 0

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "CyberArmorConfig":
        """
        Build a CyberArmorConfig entirely from environment variables.

        Reads CYBERARMOR_* environment variables.
        """
        return cls(
            api_key=_env("CYBERARMOR_API_KEY"),
            api_url=_env(
                "CYBERARMOR_API_URL",
                "https://api.cyberarmor.ai/v1",
            ),  # type: ignore[arg-type]
            tenant_id=_env("CYBERARMOR_TENANT_ID"),
            agent_id=_env("CYBERARMOR_AGENT_ID"),
            environment=_env(
                "CYBERARMOR_ENVIRONMENT", "production"
            ),  # type: ignore[arg-type]
            timeout_seconds=float(
                _env("CYBERARMOR_TIMEOUT_SECONDS", "10") or "10"
            ),
            max_retries=_env_int("CYBERARMOR_MAX_RETRIES", 3),
            audit_enabled=_env_bool("CYBERARMOR_AUDIT_ENABLED", True),
            audit_batch_size=_env_int("CYBERARMOR_AUDIT_BATCH_SIZE", 50),
            audit_flush_interval=float(
                _env("CYBERARMOR_AUDIT_FLUSH_INTERVAL", default="5") or "5"
            ),
            dlp_enabled=_env_bool("CYBERARMOR_DLP_ENABLED", True),
            injection_detection=_env_bool("CYBERARMOR_INJECTION_DETECTION", True),
            local_policy_path=_env("CYBERARMOR_LOCAL_POLICY_PATH"),
            signing_key=_env("CYBERARMOR_SIGNING_KEY"),
            verify_ssl=_env_bool("CYBERARMOR_VERIFY_SSL", True),
            log_level=_env("CYBERARMOR_LOG_LEVEL", default="WARNING") or "WARNING",
            allowed_models=_env_list("CYBERARMOR_ALLOWED_MODELS"),
            blocked_models=_env_list("CYBERARMOR_BLOCKED_MODELS"),
            token_ttl=_env_int("CYBERARMOR_TOKEN_TTL", 3600),
            max_delegation_depth=_env_int("CYBERARMOR_MAX_DELEGATION_DEPTH", 0),
        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> None:
        """Raise ValueError for obviously invalid configuration."""
        if not self.api_key and not self.local_policy_path:
            raise ValueError(
                "CyberArmorConfig requires either 'api_key' or 'local_policy_path'. "
                "Set CYBERARMOR_API_KEY or CYBERARMOR_LOCAL_POLICY_PATH."
            )
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive.")
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0.")
        if self.audit_batch_size < 1:
            raise ValueError("audit_batch_size must be >= 1.")

    def __repr__(self) -> str:
        masked = f"{'*' * 8}{self.api_key[-4:]}" if self.api_key else "None"
        return (
            f"CyberArmorConfig("
            f"api_url={self.api_url!r}, "
            f"tenant_id={self.tenant_id!r}, "
            f"agent_id={self.agent_id!r}, "
            f"environment={self.environment!r}, "
            f"api_key={masked!r})"
        )
