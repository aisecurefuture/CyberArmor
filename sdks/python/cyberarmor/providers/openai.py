"""
CyberArmor OpenAI Provider
==========================
Drop-in replacement for openai.OpenAI that intercepts chat.completions.create
to enforce policy before the call and emit an audit event after.

Usage::

    from cyberarmor.providers.openai import CyberArmorOpenAI

    client = CyberArmorOpenAI(api_key="sk-...")
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}],
    )
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Iterator, Optional

import openai
from openai import OpenAI, Stream
from openai.types.chat import ChatCompletion, ChatCompletionChunk

from cyberarmor.audit.emitter import AuditEmitter
from cyberarmor.client import CyberArmorClient
from cyberarmor.config import CyberArmorConfig
from cyberarmor.policy.decisions import DecisionType, PolicyViolationError
from cyberarmor.policy.enforcer import PolicyEnforcer

import structlog

logger = structlog.get_logger(__name__)


class _CyberArmorChatCompletions:
    """
    Proxy object that replaces ``openai_client.chat.completions`` and
    intercepts ``create`` calls to enforce CyberArmor policy.
    """

    def __init__(
        self,
        underlying_chat_completions: Any,
        enforcer: PolicyEnforcer,
        audit: AuditEmitter,
        config: CyberArmorConfig,
    ) -> None:
        self._underlying = underlying_chat_completions
        self._enforcer = enforcer
        self._audit = audit
        self._config = config

    # ------------------------------------------------------------------
    # Public interception point
    # ------------------------------------------------------------------

    def create(self, **kwargs: Any) -> ChatCompletion | Stream[ChatCompletionChunk]:
        """
        Intercept chat.completions.create.

        Steps:
        1. Build a policy request from kwargs.
        2. Evaluate policy — raise PolicyViolationError if blocked.
        3. Call the underlying OpenAI client.
        4. Emit an audit event on success.
        """
        request_id = str(uuid.uuid4())
        model = kwargs.get("model", "unknown")
        messages = kwargs.get("messages", [])
        stream = kwargs.get("stream", False)

        log = logger.bind(request_id=request_id, model=model, provider="openai")
        log.info("cyberarmor.openai.request", message_count=len(messages))

        # ---- 1. Policy enforcement ----------------------------------------
        policy_request = {
            "request_id": request_id,
            "provider": "openai",
            "model": model,
            "messages": messages,
            "parameters": {k: v for k, v in kwargs.items() if k not in ("messages",)},
        }

        decision = self._enforcer.evaluate(policy_request)
        log.info(
            "cyberarmor.openai.policy_decision",
            decision=decision.decision_type.value,
            policy_ids=decision.matched_policy_ids,
        )

        if decision.decision_type == DecisionType.BLOCK:
            log.warning(
                "cyberarmor.openai.blocked",
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
            log.info("cyberarmor.openai.messages_redacted")

        # ---- 2. Delegate to underlying client --------------------------------
        start_ts = time.monotonic()
        try:
            response = self._underlying.create(**kwargs)
        except openai.APIError as exc:
            self._audit.emit_error(
                request_id=request_id,
                provider="openai",
                model=model,
                error=str(exc),
                duration_ms=int((time.monotonic() - start_ts) * 1000),
            )
            raise

        duration_ms = int((time.monotonic() - start_ts) * 1000)

        # ---- 3. Streaming: wrap in an auditing iterator ----------------------
        if stream:
            return self._audit_stream(
                response, request_id=request_id, model=model, duration_ms=duration_ms
            )

        # ---- 4. Emit audit event ---------------------------------------------
        usage = getattr(response, "usage", None)
        self._audit.emit_completion(
            request_id=request_id,
            provider="openai",
            model=model,
            prompt_tokens=getattr(usage, "prompt_tokens", None),
            completion_tokens=getattr(usage, "completion_tokens", None),
            duration_ms=duration_ms,
            decision_type=decision.decision_type.value,
            matched_policy_ids=decision.matched_policy_ids,
        )

        log.info("cyberarmor.openai.success", duration_ms=duration_ms)
        return response

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _audit_stream(
        self,
        stream: Stream[ChatCompletionChunk],
        *,
        request_id: str,
        model: str,
        duration_ms: int,
    ) -> Iterator[ChatCompletionChunk]:
        """Wrap a streaming response to emit an audit event after completion."""
        try:
            for chunk in stream:
                yield chunk
        finally:
            self._audit.emit_completion(
                request_id=request_id,
                provider="openai",
                model=model,
                prompt_tokens=None,
                completion_tokens=None,
                duration_ms=duration_ms,
                decision_type="allow",
                matched_policy_ids=[],
            )

    # ------------------------------------------------------------------
    # Passthrough for any other methods on the completions object
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        return getattr(self._underlying, name)


class _CyberArmorChat:
    """Proxy for ``openai_client.chat`` that exposes a CyberArmor-aware completions object."""

    def __init__(
        self,
        underlying_chat: Any,
        enforcer: PolicyEnforcer,
        audit: AuditEmitter,
        config: CyberArmorConfig,
    ) -> None:
        self._underlying = underlying_chat
        self.completions = _CyberArmorChatCompletions(
            underlying_chat.completions, enforcer, audit, config
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._underlying, name)


class CyberArmorOpenAI:
    """
    Drop-in replacement for ``openai.OpenAI``.

    All constructor arguments are forwarded to ``openai.OpenAI``.  An optional
    ``cyberarmor_client`` keyword argument may be supplied to reuse an
    existing :class:`~cyberarmor.client.CyberArmorClient`; if omitted, a
    default client is constructed from environment variables.

    Example::

        client = CyberArmorOpenAI(api_key=os.environ["OPENAI_API_KEY"])
        resp = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Explain quantum computing."}],
        )
    """

    def __init__(
        self,
        *,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        **openai_kwargs: Any,
    ) -> None:
        # Resolve the CyberArmor client
        if cyberarmor_client is None:
            cyberarmor_client = CyberArmorClient()

        self._ca_client = cyberarmor_client

        # Build the underlying OpenAI client
        self._openai = OpenAI(**openai_kwargs)

        # Replace the chat namespace with our proxy
        self.chat = _CyberArmorChat(
            self._openai.chat,
            enforcer=cyberarmor_client.policy,
            audit=cyberarmor_client.audit,
            config=cyberarmor_client.config,
        )

    # ------------------------------------------------------------------
    # Forward everything else to the underlying OpenAI client
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        return getattr(self._openai, name)

    # ------------------------------------------------------------------
    # Context manager support (mirrors openai.OpenAI)
    # ------------------------------------------------------------------

    def __enter__(self) -> "CyberArmorOpenAI":
        self._openai.__enter__()
        return self

    def __exit__(self, *args: Any) -> None:
        self._openai.__exit__(*args)
