"""
CyberArmor Anthropic Provider
==============================
Drop-in replacement for ``anthropic.Anthropic`` that enforces CyberArmor
policy before every ``messages.create`` call and emits an audit event on
success.

Usage::

    from cyberarmor.providers.anthropic import CyberArmorAnthropic

    client = CyberArmorAnthropic(api_key="sk-ant-...")
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello"}],
    )
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Iterator, Optional

import anthropic
from anthropic import Anthropic
from anthropic.types import Message, RawMessageStreamEvent

from cyberarmor.audit.emitter import AuditEmitter
from cyberarmor.client import CyberArmorClient
from cyberarmor.config import CyberArmorConfig
from cyberarmor.policy.decisions import DecisionType, PolicyViolationError
from cyberarmor.policy.enforcer import PolicyEnforcer

import structlog

logger = structlog.get_logger(__name__)


class _CyberArmorMessages:
    """
    Proxy that replaces ``anthropic_client.messages`` and intercepts
    ``create`` and ``stream`` calls to enforce CyberArmor policy.
    """

    def __init__(
        self,
        underlying_messages: Any,
        enforcer: PolicyEnforcer,
        audit: AuditEmitter,
        config: CyberArmorConfig,
    ) -> None:
        self._underlying = underlying_messages
        self._enforcer = enforcer
        self._audit = audit
        self._config = config

    # ------------------------------------------------------------------
    # Primary interception point
    # ------------------------------------------------------------------

    def create(self, **kwargs: Any) -> Message:
        """
        Intercept messages.create.

        1. Evaluate policy.
        2. Raise PolicyViolationError if blocked.
        3. Forward to Anthropic API.
        4. Emit audit event.
        """
        request_id = str(uuid.uuid4())
        model = kwargs.get("model", "unknown")
        messages = kwargs.get("messages", [])
        stream = kwargs.get("stream", False)

        log = logger.bind(request_id=request_id, model=model, provider="anthropic")
        log.info("cyberarmor.anthropic.request", message_count=len(messages))

        # ---- 1. Policy enforcement ----------------------------------------
        system_prompt = kwargs.get("system", None)
        policy_request = {
            "request_id": request_id,
            "provider": "anthropic",
            "model": model,
            "messages": messages,
            "system": system_prompt,
            "parameters": {
                k: v
                for k, v in kwargs.items()
                if k not in ("messages", "system")
            },
        }

        decision = self._enforcer.evaluate(policy_request)
        log.info(
            "cyberarmor.anthropic.policy_decision",
            decision=decision.decision_type.value,
            policy_ids=decision.matched_policy_ids,
        )

        if decision.decision_type == DecisionType.BLOCK:
            log.warning(
                "cyberarmor.anthropic.blocked",
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
            log.info("cyberarmor.anthropic.messages_redacted")

        # ---- 2. Delegate to Anthropic API ------------------------------------
        start_ts = time.monotonic()
        try:
            response = self._underlying.create(**kwargs)
        except anthropic.APIError as exc:
            self._audit.emit_error(
                request_id=request_id,
                provider="anthropic",
                model=model,
                error=str(exc),
                duration_ms=int((time.monotonic() - start_ts) * 1000),
            )
            raise

        duration_ms = int((time.monotonic() - start_ts) * 1000)

        # ---- 3. Streaming: wrap in an auditing iterator ---------------------
        if stream:
            return self._audit_stream(
                response,
                request_id=request_id,
                model=model,
                duration_ms=duration_ms,
            )

        # ---- 4. Emit audit event ---------------------------------------------
        usage = getattr(response, "usage", None)
        self._audit.emit_completion(
            request_id=request_id,
            provider="anthropic",
            model=model,
            prompt_tokens=getattr(usage, "input_tokens", None),
            completion_tokens=getattr(usage, "output_tokens", None),
            duration_ms=duration_ms,
            decision_type=decision.decision_type.value,
            matched_policy_ids=decision.matched_policy_ids,
        )

        log.info("cyberarmor.anthropic.success", duration_ms=duration_ms)
        return response

    # ------------------------------------------------------------------
    # Streaming helper
    # ------------------------------------------------------------------

    def _audit_stream(
        self,
        stream: Any,
        *,
        request_id: str,
        model: str,
        duration_ms: int,
    ) -> Iterator[RawMessageStreamEvent]:
        """Wrap a streaming response to emit an audit event after completion."""
        try:
            for event in stream:
                yield event
        finally:
            self._audit.emit_completion(
                request_id=request_id,
                provider="anthropic",
                model=model,
                prompt_tokens=None,
                completion_tokens=None,
                duration_ms=duration_ms,
                decision_type="allow",
                matched_policy_ids=[],
            )

    # ------------------------------------------------------------------
    # stream() convenience method (Anthropic SDK v0.20+)
    # ------------------------------------------------------------------

    def stream(self, **kwargs: Any) -> Any:
        """
        Delegate to the underlying ``messages.stream`` context manager
        after enforcing policy on the request parameters.
        """
        request_id = str(uuid.uuid4())
        model = kwargs.get("model", "unknown")
        messages = kwargs.get("messages", [])

        log = logger.bind(request_id=request_id, model=model, provider="anthropic")
        log.info("cyberarmor.anthropic.stream_request", message_count=len(messages))

        policy_request = {
            "request_id": request_id,
            "provider": "anthropic",
            "model": model,
            "messages": messages,
            "system": kwargs.get("system"),
            "parameters": {k: v for k, v in kwargs.items() if k not in ("messages", "system")},
        }

        decision = self._enforcer.evaluate(policy_request)

        if decision.decision_type == DecisionType.BLOCK:
            raise PolicyViolationError(
                message=decision.reason or "Request blocked by CyberArmor policy",
                decision=decision,
                request_id=request_id,
            )

        if decision.decision_type == DecisionType.REDACT and decision.redacted_messages:
            kwargs = dict(kwargs)
            kwargs["messages"] = decision.redacted_messages

        return self._underlying.stream(**kwargs)

    # ------------------------------------------------------------------
    # Passthrough
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        return getattr(self._underlying, name)


class CyberArmorAnthropic:
    """
    Drop-in replacement for ``anthropic.Anthropic``.

    All constructor arguments are forwarded verbatim to
    ``anthropic.Anthropic``.  Optionally pass ``cyberarmor_client`` to
    reuse an existing :class:`~cyberarmor.client.CyberArmorClient`.

    Example::

        client = CyberArmorAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        msg = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=512,
            messages=[{"role": "user", "content": "Write a haiku."}],
        )
    """

    def __init__(
        self,
        *,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        **anthropic_kwargs: Any,
    ) -> None:
        if cyberarmor_client is None:
            cyberarmor_client = CyberArmorClient()

        self._ca_client = cyberarmor_client
        self._anthropic = Anthropic(**anthropic_kwargs)

        self.messages = _CyberArmorMessages(
            self._anthropic.messages,
            enforcer=cyberarmor_client.policy,
            audit=cyberarmor_client.audit,
            config=cyberarmor_client.config,
        )

    # ------------------------------------------------------------------
    # Forward everything else
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        return getattr(self._anthropic, name)

    def __enter__(self) -> "CyberArmorAnthropic":
        self._anthropic.__enter__()
        return self

    def __exit__(self, *args: Any) -> None:
        self._anthropic.__exit__(*args)
