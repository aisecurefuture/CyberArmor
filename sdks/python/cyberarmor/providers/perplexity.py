"""
CyberArmor Perplexity Provider
================================
Perplexity AI's Sonar models expose an OpenAI-compatible REST API.
This provider subclasses :class:`~cyberarmor.providers.openai.CyberArmorOpenAI`
and fixes the ``base_url`` to ``https://api.perplexity.ai``.

Usage::

    from cyberarmor.providers.perplexity import CyberArmorPerplexity

    client = CyberArmorPerplexity(api_key=os.environ["PERPLEXITY_API_KEY"])
    response = client.chat.completions.create(
        model="sonar-pro",
        messages=[
            {"role": "system", "content": "Be precise and concise."},
            {"role": "user", "content": "How many moons does Saturn have?"},
        ],
    )
    print(response.choices[0].message.content)
"""

from __future__ import annotations

from typing import Any, Optional

from cyberarmor.client import CyberArmorClient
from cyberarmor.providers.openai import CyberArmorOpenAI

import structlog

logger = structlog.get_logger(__name__)

#: Canonical Perplexity API base URL (OpenAI-compatible).
PERPLEXITY_BASE_URL: str = "https://api.perplexity.ai"

#: Recommended default model.
PERPLEXITY_DEFAULT_MODEL: str = "sonar-pro"


class CyberArmorPerplexity(CyberArmorOpenAI):
    """
    Drop-in CyberArmor-wrapped client for Perplexity AI Sonar models.

    Because Perplexity's API is OpenAI-compatible, this class is a thin
    subclass of :class:`~cyberarmor.providers.openai.CyberArmorOpenAI`
    that sets ``base_url`` to ``https://api.perplexity.ai`` automatically.

    Perplexity supports additional request fields such as ``search_domain_filter``,
    ``return_images``, ``return_related_questions``, and ``search_recency_filter``;
    these are forwarded transparently through the ``**kwargs`` mechanism.

    Args:
        api_key: Perplexity API key.
        base_url: Override the Perplexity base URL (default:
            ``https://api.perplexity.ai``).
        cyberarmor_client: Optional existing
            :class:`~cyberarmor.client.CyberArmorClient`.
        **openai_kwargs: Additional keyword arguments forwarded to
            ``openai.OpenAI``.

    Example::

        import os
        from cyberarmor.providers.perplexity import CyberArmorPerplexity

        client = CyberArmorPerplexity(api_key=os.environ["PERPLEXITY_API_KEY"])
        resp = client.chat.completions.create(
            model="sonar-pro",
            messages=[{"role": "user", "content": "Latest AI news?"}],
        )
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: str = PERPLEXITY_BASE_URL,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        **openai_kwargs: Any,
    ) -> None:
        if base_url != PERPLEXITY_BASE_URL:
            logger.warning(
                "cyberarmor.perplexity.custom_base_url",
                base_url=base_url,
                message=(
                    "A non-default base_url was supplied to CyberArmorPerplexity. "
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
            "cyberarmor.perplexity.initialized",
            base_url=base_url,
        )

    # ------------------------------------------------------------------
    # Convenience factory
    # ------------------------------------------------------------------

    @classmethod
    def from_env(
        cls,
        *,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        **openai_kwargs: Any,
    ) -> "CyberArmorPerplexity":
        """
        Construct a :class:`CyberArmorPerplexity` client whose API key is
        read from the ``PERPLEXITY_API_KEY`` environment variable.

        Raises:
            EnvironmentError: if ``PERPLEXITY_API_KEY`` is not set.
        """
        import os

        api_key = os.environ.get("PERPLEXITY_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "The PERPLEXITY_API_KEY environment variable is not set. "
                "Please export your Perplexity API key before using "
                "CyberArmorPerplexity.from_env()."
            )

        return cls(
            api_key=api_key,
            cyberarmor_client=cyberarmor_client,
            **openai_kwargs,
        )

    # ------------------------------------------------------------------
    # Perplexity-specific model catalogue helpers
    # ------------------------------------------------------------------

    @staticmethod
    def available_models() -> list[str]:
        """
        Return a static list of known Perplexity Sonar model identifiers.

        Note: this list is maintained manually and may lag behind the
        Perplexity model catalogue.  Prefer querying the API directly for
        an authoritative list.
        """
        return [
            "sonar",
            "sonar-pro",
            "sonar-reasoning",
            "sonar-reasoning-pro",
            "sonar-deep-research",
        ]
