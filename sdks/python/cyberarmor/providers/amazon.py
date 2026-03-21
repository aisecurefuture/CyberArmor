"""
CyberArmor Amazon Bedrock Provider
====================================
Wraps a ``boto3`` Bedrock Runtime client to enforce CyberArmor policy before
``invoke_model`` and ``converse`` calls, and emit audit events on success.

Usage::

    import boto3
    from cyberarmor.providers.amazon import CyberArmorBedrock

    boto_client = boto3.client("bedrock-runtime", region_name="us-east-1")
    client = CyberArmorBedrock(bedrock_client=boto_client)

    # Using invoke_model (raw byte payload)
    response = client.invoke_model(
        modelId="anthropic.claude-3-sonnet-20240229-v1:0",
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "Hello"}],
        }),
        contentType="application/json",
        accept="application/json",
    )

    # Using converse (unified Bedrock API)
    response = client.converse(
        modelId="amazon.titan-text-express-v1",
        messages=[{"role": "user", "content": [{"text": "Hello"}]}],
    )
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional

import structlog

from cyberarmor.audit.emitter import AuditEmitter
from cyberarmor.client import CyberArmorClient
from cyberarmor.config import CyberArmorConfig
from cyberarmor.policy.decisions import DecisionType, PolicyViolationError
from cyberarmor.policy.enforcer import PolicyEnforcer

logger = structlog.get_logger(__name__)


def _extract_messages_from_body(body: Any, model_id: str) -> List[dict]:
    """
    Best-effort extraction of human-readable messages from a Bedrock request
    body (bytes | str | dict).  Handles Anthropic, Amazon Titan, AI21, and
    Cohere body formats.
    """
    if isinstance(body, (bytes, bytearray)):
        try:
            body = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return [{"role": "user", "content": "<binary body>"}]

    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return [{"role": "user", "content": body}]

    if not isinstance(body, dict):
        return [{"role": "user", "content": str(body)}]

    # Anthropic Claude on Bedrock
    if "messages" in body:
        msgs = []
        for m in body["messages"]:
            content = m.get("content", "")
            if isinstance(content, list):
                content = " ".join(
                    part.get("text", "") if isinstance(part, dict) else str(part)
                    for part in content
                )
            msgs.append({"role": m.get("role", "user"), "content": content})
        if "system" in body:
            msgs.insert(0, {"role": "system", "content": body["system"]})
        return msgs

    # Amazon Titan
    if "inputText" in body:
        return [{"role": "user", "content": body["inputText"]}]

    # AI21 Jurassic
    if "prompt" in body:
        return [{"role": "user", "content": body["prompt"]}]

    # Cohere Command
    if "message" in body:
        return [{"role": "user", "content": body["message"]}]

    # Meta Llama (Bedrock)
    if "prompt" in body:
        return [{"role": "user", "content": body["prompt"]}]

    return [{"role": "user", "content": json.dumps(body)}]


def _extract_converse_messages(messages: List[dict]) -> List[dict]:
    """Normalise Bedrock Converse API message format."""
    result = []
    for m in messages:
        content = m.get("content", [])
        if isinstance(content, list):
            text = " ".join(
                block.get("text", "") if isinstance(block, dict) else str(block)
                for block in content
            )
        else:
            text = str(content)
        result.append({"role": m.get("role", "user"), "content": text})
    return result


class CyberArmorBedrock:
    """
    CyberArmor-aware wrapper around a ``boto3`` Bedrock Runtime client.

    Intercepts ``invoke_model`` and ``converse`` to enforce policy and
    emit audit events.  All other methods are forwarded verbatim to the
    underlying boto3 client.

    Args:
        bedrock_client: An existing ``boto3.client("bedrock-runtime")``
            instance.  If omitted a new one is created with default
            credential chain (region from ``AWS_DEFAULT_REGION`` env var).
        cyberarmor_client: Reuse an existing
            :class:`~cyberarmor.client.CyberArmorClient`.  A default
            client is constructed from environment variables if not provided.
        **boto_kwargs: Forwarded to ``boto3.client("bedrock-runtime")``
            when ``bedrock_client`` is not provided.
    """

    def __init__(
        self,
        bedrock_client: Optional[Any] = None,
        *,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        **boto_kwargs: Any,
    ) -> None:
        if bedrock_client is None:
            try:
                import boto3  # noqa: F401
            except ImportError as exc:
                raise ImportError(
                    "boto3 is required for CyberArmorBedrock. "
                    "Install it with: pip install cyberarmor-sdk[aws]"
                ) from exc
            import boto3

            bedrock_client = boto3.client("bedrock-runtime", **boto_kwargs)

        self._bedrock = bedrock_client

        if cyberarmor_client is None:
            cyberarmor_client = CyberArmorClient()

        self._ca_client = cyberarmor_client
        self._enforcer: PolicyEnforcer = cyberarmor_client.policy
        self._audit: AuditEmitter = cyberarmor_client.audit
        self._config: CyberArmorConfig = cyberarmor_client.config

    # ------------------------------------------------------------------
    # invoke_model interception
    # ------------------------------------------------------------------

    def invoke_model(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Policy-enforced wrapper around ``bedrock_runtime.invoke_model``.

        Raises:
            PolicyViolationError: if the request is blocked by policy.
        """
        request_id = str(uuid.uuid4())
        model_id = kwargs.get("modelId", "unknown")
        body = kwargs.get("body", b"")
        messages = _extract_messages_from_body(body, model_id)

        log = logger.bind(request_id=request_id, model=model_id, provider="bedrock")
        log.info("cyberarmor.bedrock.invoke_model", message_count=len(messages))

        # ---- Policy evaluation -------------------------------------------
        policy_request = {
            "request_id": request_id,
            "provider": "bedrock",
            "model": model_id,
            "messages": messages,
            "parameters": {k: v for k, v in kwargs.items() if k != "body"},
        }

        decision = self._enforcer.evaluate(policy_request)
        log.info(
            "cyberarmor.bedrock.policy_decision",
            decision=decision.decision_type.value,
            policy_ids=decision.matched_policy_ids,
        )

        if decision.decision_type == DecisionType.BLOCK:
            log.warning(
                "cyberarmor.bedrock.blocked",
                reason=decision.reason,
                policy_ids=decision.matched_policy_ids,
            )
            raise PolicyViolationError(
                message=decision.reason or "Request blocked by CyberArmor policy",
                decision=decision,
                request_id=request_id,
            )

        # ---- Delegate to boto3 -------------------------------------------
        start_ts = time.monotonic()
        try:
            response = self._bedrock.invoke_model(**kwargs)
        except Exception as exc:
            self._audit.emit_error(
                request_id=request_id,
                provider="bedrock",
                model=model_id,
                error=str(exc),
                duration_ms=int((time.monotonic() - start_ts) * 1000),
            )
            raise

        duration_ms = int((time.monotonic() - start_ts) * 1000)

        # ---- Audit event -------------------------------------------------
        self._audit.emit_completion(
            request_id=request_id,
            provider="bedrock",
            model=model_id,
            prompt_tokens=None,
            completion_tokens=None,
            duration_ms=duration_ms,
            decision_type=decision.decision_type.value,
            matched_policy_ids=decision.matched_policy_ids,
        )

        log.info("cyberarmor.bedrock.invoke_model_success", duration_ms=duration_ms)
        return response

    # ------------------------------------------------------------------
    # converse interception (Bedrock unified API)
    # ------------------------------------------------------------------

    def converse(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Policy-enforced wrapper around ``bedrock_runtime.converse``.

        The Bedrock Converse API provides a model-agnostic chat interface.
        """
        request_id = str(uuid.uuid4())
        model_id = kwargs.get("modelId", "unknown")
        raw_messages = kwargs.get("messages", [])
        messages = _extract_converse_messages(raw_messages)

        # Include system prompt if present
        system = kwargs.get("system", [])
        if system:
            system_text = " ".join(
                block.get("text", "") if isinstance(block, dict) else str(block)
                for block in system
            )
            messages.insert(0, {"role": "system", "content": system_text})

        log = logger.bind(request_id=request_id, model=model_id, provider="bedrock")
        log.info("cyberarmor.bedrock.converse", message_count=len(messages))

        # ---- Policy evaluation -------------------------------------------
        policy_request = {
            "request_id": request_id,
            "provider": "bedrock",
            "model": model_id,
            "messages": messages,
            "parameters": {
                k: v for k, v in kwargs.items() if k not in ("messages", "system")
            },
        }

        decision = self._enforcer.evaluate(policy_request)
        log.info(
            "cyberarmor.bedrock.policy_decision",
            decision=decision.decision_type.value,
            policy_ids=decision.matched_policy_ids,
        )

        if decision.decision_type == DecisionType.BLOCK:
            log.warning(
                "cyberarmor.bedrock.blocked",
                reason=decision.reason,
                policy_ids=decision.matched_policy_ids,
            )
            raise PolicyViolationError(
                message=decision.reason or "Request blocked by CyberArmor policy",
                decision=decision,
                request_id=request_id,
            )

        # ---- Delegate to boto3 -------------------------------------------
        start_ts = time.monotonic()
        try:
            response = self._bedrock.converse(**kwargs)
        except Exception as exc:
            self._audit.emit_error(
                request_id=request_id,
                provider="bedrock",
                model=model_id,
                error=str(exc),
                duration_ms=int((time.monotonic() - start_ts) * 1000),
            )
            raise

        duration_ms = int((time.monotonic() - start_ts) * 1000)

        # Extract token usage from Converse response
        usage = response.get("usage", {})
        self._audit.emit_completion(
            request_id=request_id,
            provider="bedrock",
            model=model_id,
            prompt_tokens=usage.get("inputTokens"),
            completion_tokens=usage.get("outputTokens"),
            duration_ms=duration_ms,
            decision_type=decision.decision_type.value,
            matched_policy_ids=decision.matched_policy_ids,
        )

        log.info("cyberarmor.bedrock.converse_success", duration_ms=duration_ms)
        return response

    # ------------------------------------------------------------------
    # invoke_model_with_response_stream (streaming)
    # ------------------------------------------------------------------

    def invoke_model_with_response_stream(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Policy-enforced wrapper around streaming invoke.  Policy is checked
        before the stream begins; no post-stream audit is emitted as token
        counts are not available mid-stream.
        """
        request_id = str(uuid.uuid4())
        model_id = kwargs.get("modelId", "unknown")
        body = kwargs.get("body", b"")
        messages = _extract_messages_from_body(body, model_id)

        log = logger.bind(request_id=request_id, model=model_id, provider="bedrock")
        log.info("cyberarmor.bedrock.streaming_request", message_count=len(messages))

        policy_request = {
            "request_id": request_id,
            "provider": "bedrock",
            "model": model_id,
            "messages": messages,
            "parameters": {k: v for k, v in kwargs.items() if k != "body"},
        }

        decision = self._enforcer.evaluate(policy_request)

        if decision.decision_type == DecisionType.BLOCK:
            raise PolicyViolationError(
                message=decision.reason or "Request blocked by CyberArmor policy",
                decision=decision,
                request_id=request_id,
            )

        return self._bedrock.invoke_model_with_response_stream(**kwargs)

    # ------------------------------------------------------------------
    # Passthrough for all other boto3 client methods
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        return getattr(self._bedrock, name)
