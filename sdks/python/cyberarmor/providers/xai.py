"""
CyberArmor xAI (Grok) Provider
================================
xAI's Grok models expose an OpenAI-compatible REST API, so this provider
simply subclasses :class:`~cyberarmor.providers.openai.CyberArmorOpenAI`
and fixes the ``base_url`` to ``https://api.x.ai/v1``.

Usage::

    from cyberarmor.providers.xai import CyberArmorXAI

    client = CyberArmorXAI(api_key=os.environ["XAI_API_KEY"])
    response = client.chat.completions.create(
        model="grok-2-latest",
        messages=[{"role": "user", "content": "Tell me something surprising."}],
    )
    print(response.choices[0].message.content)
"""

from __future__ import annotations

from typing import Any, Optional

from cyberarmor.client import CyberArmorClient
from cyberarmor.providers.openai import CyberArmorOpenAI

import structlog

logger = structlog.get_logger(__name__)

#: The canonical xAI API base URL (OpenAI-compatible).
XAI_BASE_URL: str = "https://api.x.ai/v1"

#: Default model to use when none is specified.
XAI_DEFAULT_MODEL: str = "grok-2-latest"


class CyberArmorXAI(CyberArmorOpenAI):
    """
    Drop-in CyberArmor-wrapped client for xAI Grok models.

    Because Grok's API is OpenAI-compatible, this class is a thin
    subclass of :class:`~cyberarmor.providers.openai.CyberArmorOpenAI`
    that sets ``base_url`` to ``https://api.x.ai/v1`` automatically.

    Args:
        api_key: xAI API key (``XAI_API_KEY`` env var is also honoured
            by the underlying openai library when ``base_url`` is set).
        cyberarmor_client: Optional existing
            :class:`~cyberarmor.client.CyberArmorClient`.
        **openai_kwargs: Any additional keyword arguments accepted by
            ``openai.OpenAI`` (e.g. ``timeout``, ``max_retries``).

    Example::

        import os
        from cyberarmor.providers.xai import CyberArmorXAI

        client = CyberArmorXAI(api_key=os.environ["XAI_API_KEY"])
        resp = client.chat.completions.create(
            model="grok-2-latest",
            messages=[{"role": "user", "content": "What is the Grok model?"}],
        )
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: str = XAI_BASE_URL,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        **openai_kwargs: Any,
    ) -> None:
        # Ensure the base_url always points at xAI even if caller passes a
        # different value (they can override explicitly, but the default is
        # the xAI endpoint).
        if base_url != XAI_BASE_URL:
            logger.warning(
                "cyberarmor.xai.custom_base_url",
                base_url=base_url,
                message=(
                    "A non-default base_url was supplied to CyberArmorXAI. "
                    "Make sure this is intentional."
                ),
            )

        kwargs: dict[str, Any] = dict(openai_kwargs)
        kwargs["base_url"] = base_url
        if api_key is not None:
            kwargs["api_key"] = api_key

        super().__init__(
            cyberarmor_client=cyberarmor_client,
            **kwargs,
        )

        logger.info(
            "cyberarmor.xai.initialized",
            base_url=base_url,
        )

    # ------------------------------------------------------------------
    # Convenience factory: create from environment variables
    # ------------------------------------------------------------------

    @classmethod
    def from_env(
        cls,
        *,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        **openai_kwargs: Any,
    ) -> "CyberArmorXAI":
        """
        Construct a :class:`CyberArmorXAI` client whose API key is read
        from the ``XAI_API_KEY`` environment variable.

        Raises:
            EnvironmentError: if ``XAI_API_KEY`` is not set.
        """
        import os

        api_key = os.environ.get("XAI_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "The XAI_API_KEY environment variable is not set. "
                "Please export your xAI API key before using CyberArmorXAI.from_env()."
            )

        return cls(
            api_key=api_key,
            cyberarmor_client=cyberarmor_client,
            **openai_kwargs,
        )
