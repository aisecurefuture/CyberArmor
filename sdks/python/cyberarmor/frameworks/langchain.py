"""
CyberArmor LangChain Integration
==================================
Provides :class:`CyberArmorCallbackHandler`, a LangChain
:class:`BaseCallbackHandler` that enforces CyberArmor policy on every LLM
call and emits structured audit events on completion.

Usage::

    from langchain_openai import ChatOpenAI
    from cyberarmor.frameworks.langchain import CyberArmorCallbackHandler

    handler = CyberArmorCallbackHandler()
    llm = ChatOpenAI(
        model="gpt-4o",
        callbacks=[handler],
    )
    result = llm.invoke("Tell me a joke.")

The handler is framework-agnostic: it works with any LangChain LLM, Chat
model, or Chain regardless of the underlying provider.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional, Union

import structlog

from cyberarmor.audit.emitter import AuditEmitter
from cyberarmor.client import CyberArmorClient
from cyberarmor.policy.decisions import DecisionType, PolicyViolationError
from cyberarmor.policy.enforcer import PolicyEnforcer

logger = structlog.get_logger(__name__)


def _messages_to_canonical(
    messages: Any,
) -> List[Dict[str, str]]:
    """
    Coerce LangChain message representations to the canonical CyberArmor
    ``[{"role": str, "content": str}, ...]`` format understood by the policy
    enforcer.
    """
    if messages is None:
        return []

    result: List[Dict[str, str]] = []

    def _handle_single(msg: Any) -> None:
        if isinstance(msg, dict):
            result.append(
                {
                    "role": msg.get("role", msg.get("type", "user")),
                    "content": msg.get("content", str(msg)),
                }
            )
        elif isinstance(msg, str):
            result.append({"role": "user", "content": msg})
        elif hasattr(msg, "type") and hasattr(msg, "content"):
            # LangChain BaseMessage subclasses
            type_to_role = {
                "human": "user",
                "ai": "assistant",
                "system": "system",
                "function": "function",
                "tool": "tool",
            }
            role = type_to_role.get(getattr(msg, "type", "human"), "user")
            content = msg.content
            if isinstance(content, list):
                content = " ".join(
                    part.get("text", str(part)) if isinstance(part, dict) else str(part)
                    for part in content
                )
            result.append({"role": role, "content": str(content)})
        else:
            result.append({"role": "user", "content": str(msg)})

    # LangChain passes a List[List[BaseMessage]] to on_llm_start
    if isinstance(messages, list):
        for item in messages:
            if isinstance(item, list):
                for sub in item:
                    _handle_single(sub)
            else:
                _handle_single(item)
    else:
        _handle_single(messages)

    return result


class CyberArmorCallbackHandler:
    """
    LangChain ``BaseCallbackHandler`` that integrates CyberArmor policy
    enforcement and audit emission into any LangChain chain or agent.

    The handler is deliberately implemented without inheriting from
    ``langchain_core.callbacks.BaseCallbackHandler`` at class-definition
    time so that LangChain is an *optional* dependency.  When LangChain is
    present the class is registered as a proper subclass via the
    ``__init_subclass__`` mechanism automatically.

    If you prefer an explicit import, install LangChain and import normally;
    duck-typing ensures the handler is accepted by the LangChain callback
    system regardless.

    Args:
        cyberarmor_client: Optional existing
            :class:`~cyberarmor.client.CyberArmorClient`.
        raise_on_violation: If ``True`` (default), re-raise
            :class:`~cyberarmor.policy.decisions.PolicyViolationError` from
            ``on_llm_start``.  Set to ``False`` to log and continue (useful
            in observe-only mode).
    """

    raise_error = True
    ignore_llm = False
    ignore_chain = False
    ignore_agent = False

    def __init__(
        self,
        *,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        raise_on_violation: bool = True,
    ) -> None:
        if cyberarmor_client is None:
            cyberarmor_client = CyberArmorClient()

        self._ca_client = cyberarmor_client
        self._enforcer: PolicyEnforcer = cyberarmor_client.policy
        self._audit: AuditEmitter = cyberarmor_client.audit
        self._raise_on_violation = raise_on_violation

        # Run-time state keyed by run_id
        self._run_start_times: Dict[str, float] = {}
        self._run_models: Dict[str, str] = {}
        self._run_messages: Dict[str, List[dict]] = {}

    # ------------------------------------------------------------------
    # LLM callbacks
    # ------------------------------------------------------------------

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """
        Called before an LLM generates a response.

        Extracts the model name and prompt messages, evaluates policy,
        and raises :class:`PolicyViolationError` if the call is blocked.
        """
        request_id = str(run_id) if run_id else str(uuid.uuid4())
        model = (
            serialized.get("kwargs", {}).get("model_name")
            or serialized.get("name", "unknown")
        )

        messages = [{"role": "user", "content": p} for p in (prompts or [])]

        log = logger.bind(request_id=request_id, model=model, provider="langchain")
        log.info("cyberarmor.langchain.llm_start", prompt_count=len(prompts))

        self._run_start_times[request_id] = time.monotonic()
        self._run_models[request_id] = model
        self._run_messages[request_id] = messages

        policy_request = {
            "request_id": request_id,
            "provider": "langchain",
            "model": model,
            "messages": messages,
            "metadata": metadata or {},
            "tags": tags or [],
        }

        decision = self._enforcer.evaluate(policy_request)
        log.info(
            "cyberarmor.langchain.policy_decision",
            decision=decision.decision_type.value,
            policy_ids=decision.matched_policy_ids,
        )

        if decision.decision_type == DecisionType.BLOCK:
            log.warning(
                "cyberarmor.langchain.blocked",
                reason=decision.reason,
                policy_ids=decision.matched_policy_ids,
            )
            if self._raise_on_violation:
                raise PolicyViolationError(
                    message=decision.reason or "Request blocked by CyberArmor policy",
                    decision=decision,
                    request_id=request_id,
                )

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[Any]],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """
        Called before a *Chat* model generates a response.

        Delegates to ``on_llm_start`` after converting structured messages
        to the canonical format and flattening them into strings for
        compatibility.
        """
        request_id = str(run_id) if run_id else str(uuid.uuid4())
        model = (
            serialized.get("kwargs", {}).get("model_name")
            or serialized.get("name", "unknown")
        )

        canonical = _messages_to_canonical(messages)
        self._run_start_times[request_id] = time.monotonic()
        self._run_models[request_id] = model
        self._run_messages[request_id] = canonical

        log = logger.bind(request_id=request_id, model=model, provider="langchain")
        log.info(
            "cyberarmor.langchain.chat_model_start",
            message_count=len(canonical),
        )

        policy_request = {
            "request_id": request_id,
            "provider": "langchain",
            "model": model,
            "messages": canonical,
            "metadata": metadata or {},
            "tags": tags or [],
        }

        decision = self._enforcer.evaluate(policy_request)

        if decision.decision_type == DecisionType.BLOCK:
            log.warning(
                "cyberarmor.langchain.blocked",
                reason=decision.reason,
                policy_ids=decision.matched_policy_ids,
            )
            if self._raise_on_violation:
                raise PolicyViolationError(
                    message=decision.reason or "Request blocked by CyberArmor policy",
                    decision=decision,
                    request_id=request_id,
                )

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """
        Called after an LLM or Chat model returns a successful response.

        Emits a CyberArmor audit event with token usage if available.
        """
        request_id = str(run_id) if run_id else "unknown"
        start_ts = self._run_start_times.pop(request_id, time.monotonic())
        model = self._run_models.pop(request_id, "unknown")
        self._run_messages.pop(request_id, None)

        duration_ms = int((time.monotonic() - start_ts) * 1000)

        prompt_tokens: Optional[int] = None
        completion_tokens: Optional[int] = None

        llm_output = getattr(response, "llm_output", None) or {}
        token_usage = llm_output.get("token_usage", {}) if isinstance(llm_output, dict) else {}
        if token_usage:
            prompt_tokens = token_usage.get("prompt_tokens")
            completion_tokens = token_usage.get("completion_tokens")

        self._audit.emit_completion(
            request_id=request_id,
            provider="langchain",
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            duration_ms=duration_ms,
            decision_type="allow",
            matched_policy_ids=[],
        )

        logger.info(
            "cyberarmor.langchain.llm_end",
            request_id=request_id,
            model=model,
            duration_ms=duration_ms,
        )

    def on_llm_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when an LLM call raises an exception.

        Emits a CyberArmor error audit event.
        """
        request_id = str(run_id) if run_id else "unknown"
        start_ts = self._run_start_times.pop(request_id, time.monotonic())
        model = self._run_models.pop(request_id, "unknown")
        self._run_messages.pop(request_id, None)

        duration_ms = int((time.monotonic() - start_ts) * 1000)

        logger.error(
            "cyberarmor.langchain.llm_error",
            request_id=request_id,
            model=model,
            error=str(error),
            duration_ms=duration_ms,
        )

        self._audit.emit_error(
            request_id=request_id,
            provider="langchain",
            model=model,
            error=str(error),
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # Chain callbacks
    # ------------------------------------------------------------------

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain begins execution."""
        chain_name = serialized.get("name", "UnknownChain")
        logger.info(
            "cyberarmor.langchain.chain_start",
            chain=chain_name,
            run_id=str(run_id),
            input_keys=list(inputs.keys()) if isinstance(inputs, dict) else [],
        )

    def on_chain_end(
        self,
        outputs: Dict[str, Any],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain finishes execution."""
        logger.info(
            "cyberarmor.langchain.chain_end",
            run_id=str(run_id),
            output_keys=list(outputs.keys()) if isinstance(outputs, dict) else [],
        )

    def on_chain_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain raises an exception."""
        logger.error(
            "cyberarmor.langchain.chain_error",
            run_id=str(run_id),
            error=str(error),
        )

    # ------------------------------------------------------------------
    # Tool callbacks
    # ------------------------------------------------------------------

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool begins execution."""
        tool_name = serialized.get("name", "UnknownTool")
        logger.info(
            "cyberarmor.langchain.tool_start",
            tool=tool_name,
            run_id=str(run_id),
        )

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool finishes execution."""
        logger.info(
            "cyberarmor.langchain.tool_end",
            run_id=str(run_id),
            output_length=len(output) if isinstance(output, str) else None,
        )

    def on_tool_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool raises an exception."""
        logger.error(
            "cyberarmor.langchain.tool_error",
            run_id=str(run_id),
            error=str(error),
        )
