"""
CyberArmor Microsoft Azure OpenAI Provider
===========================================
Drop-in replacement for ``openai.AzureOpenAI`` that enforces CyberArmor
policy before every ``chat.completions.create`` call and emits an audit
event on success.

Azure OpenAI uses a deployment-centric URL structure:
``https://{resource}.openai.azure.com/openai/deployments/{deployment}/...``

Usage::

    from cyberarmor.providers.microsoft import CyberArmorAzureOpenAI

    client = CyberArmorAzureOpenAI(
        azure_endpoint="https://my-resource.openai.azure.com",
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        api_version="2024-12-01-preview",
        azure_deployment="gpt-4o",   # default deployment
    )
    response = client.chat.completions.create(
        model="gpt-4o",              # same as azure_deployment
        messages=[{"role": "user", "content": "Hello from Azure!"}],
    )
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Iterator, Optional

import openai
from openai import AzureOpenAI, Stream
from openai.types.chat import ChatCompletion, ChatCompletionChunk

from cyberarmor.audit.emitter import AuditEmitter
from cyberarmor.client import CyberArmorClient
from cyberarmor.config import CyberArmorConfig
from cyberarmor.policy.decisions import DecisionType, PolicyViolationError
from cyberarmor.policy.enforcer import PolicyEnforcer

import structlog

logger = structlog.get_logger(__name__)


class _AzureCyberArmorChatCompletions:
    """
    Proxy object that replaces ``azure_client.chat.completions`` and
    intercepts ``create`` calls to enforce CyberArmor policy.
    """

    def __init__(
        self,
        underlying: Any,
        enforcer: PolicyEnforcer,
        audit: AuditEmitter,
        config: CyberArmorConfig,
        azure_deployment: Optional[str],
    ) -> None:
        self._underlying = underlying
        self._enforcer = enforcer
        self._audit = audit
        self._config = config
        self._azure_deployment = azure_deployment

    def create(self, **kwargs: Any) -> ChatCompletion | Stream[ChatCompletionChunk]:
        """
        Intercept chat.completions.create for Azure OpenAI.

        The effective model identifier used for policy evaluation is the
        ``model`` kwarg, which for Azure OpenAI corresponds to the deployment
        name.
        """
        request_id = str(uuid.uuid4())
        # Azure uses 'model' to mean the deployment name
        model = kwargs.get("model", self._azure_deployment or "unknown")
        messages = kwargs.get("messages", [])
        stream = kwargs.get("stream", False)

        log = logger.bind(
            request_id=request_id,
            model=model,
            provider="azure_openai",
            deployment=self._azure_deployment,
        )
        log.info("cyberarmor.azure.request", message_count=len(messages))

        # ---- Policy evaluation -------------------------------------------
        policy_request = {
            "request_id": request_id,
            "provider": "azure_openai",
            "model": model,
            "messages": messages,
            "parameters": {k: v for k, v in kwargs.items() if k != "messages"},
            "metadata": {
                "azure_deployment": self._azure_deployment,
            },
        }

        decision = self._enforcer.evaluate(policy_request)
        log.info(
            "cyberarmor.azure.policy_decision",
            decision=decision.decision_type.value,
            policy_ids=decision.matched_policy_ids,
        )

        if decision.decision_type == DecisionType.BLOCK:
            log.warning(
                "cyberarmor.azure.blocked",
                reason=decision.reason,
                policy_ids=decision.matched_policy_ids,
            )
            raise PolicyViolationError(
                message=decision.reason or "Request blocked by CyberArmor policy",
                decision=decision,
                request_id=request_id,
            )

        if decision.decision_type == DecisionType.REDACT and decision.redacted_messages:
            kwargs = dict(kwargs)
            kwargs["messages"] = decision.redacted_messages
            log.info("cyberarmor.azure.messages_redacted")

        # ---- Delegate to Azure OpenAI SDK --------------------------------
        start_ts = time.monotonic()
        try:
            response = self._underlying.create(**kwargs)
        except openai.APIError as exc:
            self._audit.emit_error(
                request_id=request_id,
                provider="azure_openai",
                model=model,
                error=str(exc),
                duration_ms=int((time.monotonic() - start_ts) * 1000),
            )
            raise

        duration_ms = int((time.monotonic() - start_ts) * 1000)

        if stream:
            return self._audit_stream(
                response,
                request_id=request_id,
                model=model,
                duration_ms=duration_ms,
            )

        # ---- Audit event -------------------------------------------------
        usage = getattr(response, "usage", None)
        self._audit.emit_completion(
            request_id=request_id,
            provider="azure_openai",
            model=model,
            prompt_tokens=getattr(usage, "prompt_tokens", None),
            completion_tokens=getattr(usage, "completion_tokens", None),
            duration_ms=duration_ms,
            decision_type=decision.decision_type.value,
            matched_policy_ids=decision.matched_policy_ids,
        )

        log.info("cyberarmor.azure.success", duration_ms=duration_ms)
        return response

    # ------------------------------------------------------------------
    # Streaming helper
    # ------------------------------------------------------------------

    def _audit_stream(
        self,
        stream: Stream[ChatCompletionChunk],
        *,
        request_id: str,
        model: str,
        duration_ms: int,
    ) -> Iterator[ChatCompletionChunk]:
        try:
            for chunk in stream:
                yield chunk
        finally:
            self._audit.emit_completion(
                request_id=request_id,
                provider="azure_openai",
                model=model,
                prompt_tokens=None,
                completion_tokens=None,
                duration_ms=duration_ms,
                decision_type="allow",
                matched_policy_ids=[],
            )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._underlying, name)


class _AzureCyberArmorChat:
    """Proxy for ``azure_client.chat`` exposing the CyberArmor completions proxy."""

    def __init__(
        self,
        underlying_chat: Any,
        enforcer: PolicyEnforcer,
        audit: AuditEmitter,
        config: CyberArmorConfig,
        azure_deployment: Optional[str],
    ) -> None:
        self._underlying = underlying_chat
        self.completions = _AzureCyberArmorChatCompletions(
            underlying_chat.completions,
            enforcer,
            audit,
            config,
            azure_deployment,
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._underlying, name)


class CyberArmorAzureOpenAI:
    """
    Drop-in replacement for ``openai.AzureOpenAI`` with CyberArmor policy
    enforcement and audit emission.

    Args:
        azure_endpoint: The Azure OpenAI resource endpoint, e.g.
            ``https://my-resource.openai.azure.com``.
        api_key: Azure OpenAI API key (or use ``AZURE_OPENAI_API_KEY`` env var).
        api_version: Azure OpenAI API version string, e.g. ``"2024-12-01-preview"``.
        azure_deployment: Default deployment / model name.  Used as the
            ``model`` value when one is not explicitly specified in
            ``chat.completions.create``.
        azure_ad_token: Azure Active Directory token for Entra ID auth.
        azure_ad_token_provider: Callable that returns an Azure AD token.
        cyberarmor_client: Optional existing
            :class:`~cyberarmor.client.CyberArmorClient`.
        **openai_kwargs: Additional kwargs forwarded to ``openai.AzureOpenAI``.

    Example::

        import os
        from cyberarmor.providers.microsoft import CyberArmorAzureOpenAI

        client = CyberArmorAzureOpenAI(
            azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
            api_key=os.environ["AZURE_OPENAI_API_KEY"],
            api_version="2024-12-01-preview",
            azure_deployment="gpt-4o",
        )
        resp = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello, Azure!"}],
        )
    """

    def __init__(
        self,
        *,
        azure_endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        api_version: Optional[str] = None,
        azure_deployment: Optional[str] = None,
        azure_ad_token: Optional[str] = None,
        azure_ad_token_provider: Optional[Any] = None,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        **openai_kwargs: Any,
    ) -> None:
        if cyberarmor_client is None:
            cyberarmor_client = CyberArmorClient()

        self._ca_client = cyberarmor_client
        self._azure_deployment = azure_deployment

        # Build kwargs for AzureOpenAI
        az_kwargs: dict[str, Any] = dict(openai_kwargs)
        if azure_endpoint is not None:
            az_kwargs["azure_endpoint"] = azure_endpoint
        if api_key is not None:
            az_kwargs["api_key"] = api_key
        if api_version is not None:
            az_kwargs["api_version"] = api_version
        if azure_deployment is not None:
            az_kwargs["azure_deployment"] = azure_deployment
        if azure_ad_token is not None:
            az_kwargs["azure_ad_token"] = azure_ad_token
        if azure_ad_token_provider is not None:
            az_kwargs["azure_ad_token_provider"] = azure_ad_token_provider

        self._azure = AzureOpenAI(**az_kwargs)

        self.chat = _AzureCyberArmorChat(
            self._azure.chat,
            enforcer=cyberarmor_client.policy,
            audit=cyberarmor_client.audit,
            config=cyberarmor_client.config,
            azure_deployment=azure_deployment,
        )

        logger.info(
            "cyberarmor.azure.initialized",
            endpoint=azure_endpoint,
            deployment=azure_deployment,
            api_version=api_version,
        )

    # ------------------------------------------------------------------
    # Convenience factory: read credentials from environment
    # ------------------------------------------------------------------

    @classmethod
    def from_env(
        cls,
        *,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        **openai_kwargs: Any,
    ) -> "CyberArmorAzureOpenAI":
        """
        Build a :class:`CyberArmorAzureOpenAI` client from environment
        variables:

        - ``AZURE_OPENAI_ENDPOINT``
        - ``AZURE_OPENAI_API_KEY``
        - ``AZURE_OPENAI_API_VERSION`` (optional, defaults to latest)
        - ``AZURE_OPENAI_DEPLOYMENT`` (optional)
        """
        import os

        endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
        api_key = os.environ.get("AZURE_OPENAI_API_KEY")
        api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")
        deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT")

        if not endpoint:
            raise EnvironmentError(
                "AZURE_OPENAI_ENDPOINT environment variable is not set."
            )
        if not api_key:
            raise EnvironmentError(
                "AZURE_OPENAI_API_KEY environment variable is not set."
            )

        return cls(
            azure_endpoint=endpoint,
            api_key=api_key,
            api_version=api_version,
            azure_deployment=deployment,
            cyberarmor_client=cyberarmor_client,
            **openai_kwargs,
        )

    # ------------------------------------------------------------------
    # Forward attribute access to underlying AzureOpenAI client
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        return getattr(self._azure, name)

    def __enter__(self) -> "CyberArmorAzureOpenAI":
        self._azure.__enter__()
        return self

    def __exit__(self, *args: Any) -> None:
        self._azure.__exit__(*args)
