"""
CyberArmor Meta / Llama Provider
==================================
Supports Llama models accessed via Together AI, Fireworks AI, or a local
Ollama instance — all of which expose an OpenAI-compatible REST API.

This provider subclasses :class:`~cyberarmor.providers.openai.CyberArmorOpenAI`
with a configurable ``base_url`` so callers can point it at any OpenAI-
compatible inference endpoint that serves Meta Llama models.

Usage::

    # Together AI
    from cyberarmor.providers.meta import CyberArmorMeta
    client = CyberArmorMeta.together(api_key=os.environ["TOGETHER_API_KEY"])

    # Fireworks AI
    client = CyberArmorMeta.fireworks(api_key=os.environ["FIREWORKS_API_KEY"])

    # Local Ollama
    client = CyberArmorMeta.ollama()

    # Generic — any base URL
    client = CyberArmorMeta(
        base_url="https://my-inference-server/v1",
        api_key="sk-local",
    )

    response = client.chat.completions.create(
        model="meta-llama/Llama-3.3-70B-Instruct-Turbo",
        messages=[{"role": "user", "content": "What is the capital of France?"}],
    )
"""

from __future__ import annotations

from typing import Any, Optional

from cyberarmor.client import CyberArmorClient
from cyberarmor.providers.openai import CyberArmorOpenAI

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Well-known base URLs
# ---------------------------------------------------------------------------

TOGETHER_BASE_URL: str = "https://api.together.xyz/v1"
FIREWORKS_BASE_URL: str = "https://api.fireworks.ai/inference/v1"
OLLAMA_BASE_URL: str = "http://localhost:11434/v1"

# Default model identifiers for each backend
TOGETHER_DEFAULT_MODEL: str = "meta-llama/Llama-3.3-70B-Instruct-Turbo"
FIREWORKS_DEFAULT_MODEL: str = "accounts/fireworks/models/llama-v3p3-70b-instruct"
OLLAMA_DEFAULT_MODEL: str = "llama3.3"


class CyberArmorMeta(CyberArmorOpenAI):
    """
    CyberArmor-wrapped OpenAI-compatible client for Meta Llama models.

    Supports Together AI, Fireworks AI, and local Ollama deployments.
    All CyberArmor policy enforcement and audit functionality is inherited
    from :class:`~cyberarmor.providers.openai.CyberArmorOpenAI`.

    Args:
        base_url: The base URL of the OpenAI-compatible inference endpoint.
        api_key: API key for the inference service.  For local Ollama this
            can be any non-empty string (e.g. ``"ollama"``).
        cyberarmor_client: Optional existing
            :class:`~cyberarmor.client.CyberArmorClient`.
        backend_name: Informational label stored for logging purposes.
        **openai_kwargs: Additional kwargs forwarded to ``openai.OpenAI``.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: Optional[str] = None,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        backend_name: str = "meta",
        **openai_kwargs: Any,
    ) -> None:
        self._backend_name = backend_name

        kwargs: dict[str, Any] = dict(openai_kwargs)
        kwargs["base_url"] = base_url
        if api_key is not None:
            kwargs["api_key"] = api_key

        super().__init__(
            cyberarmor_client=cyberarmor_client,
            **kwargs,
        )

        logger.info(
            "cyberarmor.meta.initialized",
            backend=backend_name,
            base_url=base_url,
        )

    # ------------------------------------------------------------------
    # Named constructors for popular backends
    # ------------------------------------------------------------------

    @classmethod
    def together(
        cls,
        *,
        api_key: Optional[str] = None,
        base_url: str = TOGETHER_BASE_URL,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        **openai_kwargs: Any,
    ) -> "CyberArmorMeta":
        """
        Create a client targeting Together AI's inference API.

        If ``api_key`` is omitted, the ``TOGETHER_API_KEY`` environment
        variable is used.

        Example::

            client = CyberArmorMeta.together()
            resp = client.chat.completions.create(
                model="meta-llama/Llama-3.3-70B-Instruct-Turbo",
                messages=[{"role": "user", "content": "Hello!"}],
            )
        """
        import os

        resolved_key = api_key or os.environ.get("TOGETHER_API_KEY")
        if not resolved_key:
            raise EnvironmentError(
                "TOGETHER_API_KEY environment variable is not set and no "
                "api_key was provided to CyberArmorMeta.together()."
            )

        return cls(
            base_url=base_url,
            api_key=resolved_key,
            cyberarmor_client=cyberarmor_client,
            backend_name="together",
            **openai_kwargs,
        )

    @classmethod
    def fireworks(
        cls,
        *,
        api_key: Optional[str] = None,
        base_url: str = FIREWORKS_BASE_URL,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        **openai_kwargs: Any,
    ) -> "CyberArmorMeta":
        """
        Create a client targeting Fireworks AI's inference API.

        If ``api_key`` is omitted, the ``FIREWORKS_API_KEY`` environment
        variable is used.

        Example::

            client = CyberArmorMeta.fireworks()
            resp = client.chat.completions.create(
                model="accounts/fireworks/models/llama-v3p3-70b-instruct",
                messages=[{"role": "user", "content": "Hello!"}],
            )
        """
        import os

        resolved_key = api_key or os.environ.get("FIREWORKS_API_KEY")
        if not resolved_key:
            raise EnvironmentError(
                "FIREWORKS_API_KEY environment variable is not set and no "
                "api_key was provided to CyberArmorMeta.fireworks()."
            )

        return cls(
            base_url=base_url,
            api_key=resolved_key,
            cyberarmor_client=cyberarmor_client,
            backend_name="fireworks",
            **openai_kwargs,
        )

    @classmethod
    def ollama(
        cls,
        *,
        base_url: str = OLLAMA_BASE_URL,
        api_key: str = "ollama",
        cyberarmor_client: Optional[CyberArmorClient] = None,
        **openai_kwargs: Any,
    ) -> "CyberArmorMeta":
        """
        Create a client targeting a local Ollama instance.

        Ollama's OpenAI-compatible endpoint defaults to
        ``http://localhost:11434/v1``.  No API key is required; the value
        ``"ollama"`` is passed to satisfy the openai library's requirement
        for a non-empty api_key.

        Example::

            client = CyberArmorMeta.ollama()
            resp = client.chat.completions.create(
                model="llama3.3",
                messages=[{"role": "user", "content": "Hello!"}],
            )
        """
        return cls(
            base_url=base_url,
            api_key=api_key,
            cyberarmor_client=cyberarmor_client,
            backend_name="ollama",
            **openai_kwargs,
        )

    # ------------------------------------------------------------------
    # Model catalogue helpers
    # ------------------------------------------------------------------

    @staticmethod
    def together_models() -> list[str]:
        """Return commonly used Meta Llama models available on Together AI."""
        return [
            "meta-llama/Llama-3.3-70B-Instruct-Turbo",
            "meta-llama/Llama-3.1-405B-Instruct-Turbo",
            "meta-llama/Llama-3.1-8B-Instruct-Turbo",
            "meta-llama/Meta-Llama-3-70B-Instruct",
            "meta-llama/Meta-Llama-3-8B-Instruct",
            "meta-llama/Llama-3.2-90B-Vision-Instruct-Turbo",
        ]

    @staticmethod
    def fireworks_models() -> list[str]:
        """Return commonly used Meta Llama models available on Fireworks AI."""
        return [
            "accounts/fireworks/models/llama-v3p3-70b-instruct",
            "accounts/fireworks/models/llama-v3p1-405b-instruct",
            "accounts/fireworks/models/llama-v3p1-8b-instruct",
            "accounts/fireworks/models/llama-v3-70b-instruct",
        ]
