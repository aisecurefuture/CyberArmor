"""
CyberArmor Google AI Provider
==============================
Wraps ``google.generativeai.GenerativeModel`` to enforce CyberArmor policy
before ``generate_content`` / ``generate_content_async`` calls and emit
audit events on success.

Usage::

    from cyberarmor.providers.google import CyberArmorGoogleAI
    import google.generativeai as genai

    genai.configure(api_key="AIza...")
    client = CyberArmorGoogleAI(model_name="gemini-1.5-pro")
    response = client.generate_content("Explain neural networks.")
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Iterator, List, Optional, Union

import structlog

from cyberarmor.audit.emitter import AuditEmitter
from cyberarmor.client import CyberArmorClient
from cyberarmor.config import CyberArmorConfig
from cyberarmor.policy.decisions import DecisionType, PolicyViolationError
from cyberarmor.policy.enforcer import PolicyEnforcer

logger = structlog.get_logger(__name__)


def _contents_to_messages(
    contents: Union[str, List[Any]],
) -> List[dict]:
    """
    Normalise Google GenerativeAI ``contents`` into the canonical
    CyberArmor message list format so the policy enforcer can inspect them.
    """
    if isinstance(contents, str):
        return [{"role": "user", "content": contents}]

    messages: List[dict] = []
    for item in contents:
        if isinstance(item, str):
            messages.append({"role": "user", "content": item})
        elif hasattr(item, "role") and hasattr(item, "parts"):
            # google.generativeai.types.ContentDict / Content
            parts_text = " ".join(
                getattr(p, "text", str(p)) for p in item.parts
            )
            messages.append({"role": item.role, "content": parts_text})
        elif isinstance(item, dict):
            messages.append(
                {
                    "role": item.get("role", "user"),
                    "content": " ".join(
                        p.get("text", "") if isinstance(p, dict) else str(p)
                        for p in item.get("parts", [item.get("text", "")])
                    ),
                }
            )
        else:
            messages.append({"role": "user", "content": str(item)})
    return messages


class CyberArmorGoogleAI:
    """
    CyberArmor-aware wrapper around ``google.generativeai.GenerativeModel``.

    All keyword arguments (except ``cyberarmor_client``) are forwarded to
    ``google.generativeai.GenerativeModel``.  Policy is evaluated before
    each ``generate_content`` call; an audit event is emitted on success.

    Example::

        client = CyberArmorGoogleAI(model_name="gemini-1.5-flash")
        resp = client.generate_content(
            "Summarise the following article: ..."
        )
        print(resp.text)
    """

    def __init__(
        self,
        model_name: str = "gemini-1.5-pro",
        *,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        **google_kwargs: Any,
    ) -> None:
        try:
            import google.generativeai as genai  # noqa: F401
            from google.generativeai import GenerativeModel
        except ImportError as exc:
            raise ImportError(
                "google-generativeai is required for CyberArmorGoogleAI. "
                "Install it with: pip install cyberarmor-sdk[google]"
            ) from exc

        if cyberarmor_client is None:
            cyberarmor_client = CyberArmorClient()

        self._ca_client = cyberarmor_client
        self._enforcer: PolicyEnforcer = cyberarmor_client.policy
        self._audit: AuditEmitter = cyberarmor_client.audit
        self._config: CyberArmorConfig = cyberarmor_client.config
        self._model_name = model_name

        self._model = GenerativeModel(model_name=model_name, **google_kwargs)

    # ------------------------------------------------------------------
    # Core interception: generate_content
    # ------------------------------------------------------------------

    def generate_content(
        self,
        contents: Union[str, List[Any]],
        **kwargs: Any,
    ) -> Any:
        """
        Policy-enforced wrapper around ``GenerativeModel.generate_content``.

        Raises:
            PolicyViolationError: if the request is blocked by policy.
        """
        request_id = str(uuid.uuid4())
        messages = _contents_to_messages(contents)
        stream = kwargs.get("stream", False)

        log = logger.bind(
            request_id=request_id, model=self._model_name, provider="google"
        )
        log.info("cyberarmor.google.request", message_count=len(messages))

        # ---- Policy evaluation --------------------------------------------
        policy_request = {
            "request_id": request_id,
            "provider": "google",
            "model": self._model_name,
            "messages": messages,
            "parameters": {k: v for k, v in kwargs.items()},
        }

        decision = self._enforcer.evaluate(policy_request)
        log.info(
            "cyberarmor.google.policy_decision",
            decision=decision.decision_type.value,
            policy_ids=decision.matched_policy_ids,
        )

        if decision.decision_type == DecisionType.BLOCK:
            log.warning(
                "cyberarmor.google.blocked",
                reason=decision.reason,
                policy_ids=decision.matched_policy_ids,
            )
            raise PolicyViolationError(
                message=decision.reason or "Request blocked by CyberArmor policy",
                decision=decision,
                request_id=request_id,
            )

        if decision.decision_type == DecisionType.REDACT and decision.redacted_messages:
            # Rebuild contents as a simple string concatenation for now;
            # callers using structured Content objects will need custom handling.
            contents = "\n".join(
                m.get("content", "") for m in decision.redacted_messages
            )
            log.info("cyberarmor.google.messages_redacted")

        # ---- Delegate ------------------------------------------------------
        start_ts = time.monotonic()
        try:
            response = self._model.generate_content(contents, **kwargs)
        except Exception as exc:
            self._audit.emit_error(
                request_id=request_id,
                provider="google",
                model=self._model_name,
                error=str(exc),
                duration_ms=int((time.monotonic() - start_ts) * 1000),
            )
            raise

        duration_ms = int((time.monotonic() - start_ts) * 1000)

        if stream:
            return self._audit_stream(
                response,
                request_id=request_id,
                model=self._model_name,
                duration_ms=duration_ms,
            )

        # ---- Audit ---------------------------------------------------------
        usage_metadata = getattr(response, "usage_metadata", None)
        self._audit.emit_completion(
            request_id=request_id,
            provider="google",
            model=self._model_name,
            prompt_tokens=getattr(usage_metadata, "prompt_token_count", None),
            completion_tokens=getattr(usage_metadata, "candidates_token_count", None),
            duration_ms=duration_ms,
            decision_type=decision.decision_type.value,
            matched_policy_ids=decision.matched_policy_ids,
        )

        log.info("cyberarmor.google.success", duration_ms=duration_ms)
        return response

    # ------------------------------------------------------------------
    # Async variant
    # ------------------------------------------------------------------

    async def generate_content_async(
        self,
        contents: Union[str, List[Any]],
        **kwargs: Any,
    ) -> Any:
        """Async policy-enforced wrapper around ``generate_content_async``."""
        request_id = str(uuid.uuid4())
        messages = _contents_to_messages(contents)

        log = logger.bind(
            request_id=request_id, model=self._model_name, provider="google"
        )
        log.info("cyberarmor.google.async_request", message_count=len(messages))

        policy_request = {
            "request_id": request_id,
            "provider": "google",
            "model": self._model_name,
            "messages": messages,
            "parameters": kwargs,
        }

        decision = self._enforcer.evaluate(policy_request)

        if decision.decision_type == DecisionType.BLOCK:
            raise PolicyViolationError(
                message=decision.reason or "Request blocked by CyberArmor policy",
                decision=decision,
                request_id=request_id,
            )

        if decision.decision_type == DecisionType.REDACT and decision.redacted_messages:
            contents = "\n".join(m.get("content", "") for m in decision.redacted_messages)

        start_ts = time.monotonic()
        try:
            response = await self._model.generate_content_async(contents, **kwargs)
        except Exception as exc:
            self._audit.emit_error(
                request_id=request_id,
                provider="google",
                model=self._model_name,
                error=str(exc),
                duration_ms=int((time.monotonic() - start_ts) * 1000),
            )
            raise

        duration_ms = int((time.monotonic() - start_ts) * 1000)
        usage_metadata = getattr(response, "usage_metadata", None)
        self._audit.emit_completion(
            request_id=request_id,
            provider="google",
            model=self._model_name,
            prompt_tokens=getattr(usage_metadata, "prompt_token_count", None),
            completion_tokens=getattr(usage_metadata, "candidates_token_count", None),
            duration_ms=duration_ms,
            decision_type=decision.decision_type.value,
            matched_policy_ids=decision.matched_policy_ids,
        )

        return response

    # ------------------------------------------------------------------
    # start_chat passthrough
    # ------------------------------------------------------------------

    def start_chat(self, **kwargs: Any) -> Any:
        """Return the underlying model's chat session (not intercepted)."""
        return self._model.start_chat(**kwargs)

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
    ) -> Iterator[Any]:
        try:
            for chunk in stream:
                yield chunk
        finally:
            self._audit.emit_completion(
                request_id=request_id,
                provider="google",
                model=model,
                prompt_tokens=None,
                completion_tokens=None,
                duration_ms=duration_ms,
                decision_type="allow",
                matched_policy_ids=[],
            )

    # ------------------------------------------------------------------
    # Forward attribute access to underlying model
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        return getattr(self._model, name)
