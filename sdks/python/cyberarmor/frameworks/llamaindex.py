"""
CyberArmor LlamaIndex Integration
===================================
Provides :class:`CyberArmorInstrumentation` with a ``patch_all`` classmethod
that monkey-patches ``llama_index.core.llms.LLM.complete`` and
``llama_index.core.llms.LLM.acomplete`` to enforce CyberArmor policy before
every call and emit an audit event on success.

Usage::

    from cyberarmor.frameworks.llamaindex import CyberArmorInstrumentation

    # Apply globally (patches all LlamaIndex LLM instances)
    CyberArmorInstrumentation.patch_all()

    # Or apply to a specific LlamaIndex client
    from llama_index.llms.openai import OpenAI as LlamaOpenAI
    llm = LlamaOpenAI(model="gpt-4o")
    CyberArmorInstrumentation.patch_all(llm)
"""

from __future__ import annotations

import asyncio
import functools
import time
import uuid
from typing import Any, Callable, List, Optional

import structlog

from cyberarmor.audit.emitter import AuditEmitter
from cyberarmor.client import CyberArmorClient
from cyberarmor.policy.decisions import DecisionType, PolicyViolationError
from cyberarmor.policy.enforcer import PolicyEnforcer

logger = structlog.get_logger(__name__)

# Sentinel to detect that a method has already been patched
_CYBERARMOR_PATCHED_ATTR = "_cyberarmor_patched"


def _extract_prompt(args: tuple, kwargs: dict) -> str:
    """
    Extract the prompt string from positional or keyword arguments as
    passed to ``LLM.complete`` / ``LLM.acomplete``.
    """
    # Signature: complete(prompt, **kwargs)
    if args:
        return str(args[0])
    return str(kwargs.get("prompt", ""))


def _build_messages(prompt: str) -> List[dict]:
    """Wrap a raw prompt string into the canonical CyberArmor message list."""
    return [{"role": "user", "content": prompt}]


def _make_sync_wrapper(
    original_fn: Callable,
    method_name: str,
    enforcer: PolicyEnforcer,
    audit: AuditEmitter,
) -> Callable:
    """
    Return a synchronous wrapper around ``original_fn`` that enforces
    CyberArmor policy before the call and emits an audit event after.
    """

    @functools.wraps(original_fn)
    def wrapper(self_llm: Any, *args: Any, **kwargs: Any) -> Any:
        request_id = str(uuid.uuid4())
        prompt = _extract_prompt(args, kwargs)
        messages = _build_messages(prompt)

        # Best-effort model name extraction from LlamaIndex LLM instances
        model = (
            getattr(self_llm, "model", None)
            or getattr(self_llm, "_model_name", None)
            or type(self_llm).__name__
        )

        log = logger.bind(
            request_id=request_id,
            model=model,
            method=method_name,
            provider="llamaindex",
        )
        log.info("cyberarmor.llamaindex.request", prompt_length=len(prompt))

        # ---- Policy evaluation ------------------------------------------
        policy_request = {
            "request_id": request_id,
            "provider": "llamaindex",
            "model": model,
            "messages": messages,
            "parameters": {k: v for k, v in kwargs.items() if k != "prompt"},
        }

        decision = enforcer.evaluate(policy_request)
        log.info(
            "cyberarmor.llamaindex.policy_decision",
            decision=decision.decision_type.value,
            policy_ids=decision.matched_policy_ids,
        )

        if decision.decision_type == DecisionType.BLOCK:
            log.warning(
                "cyberarmor.llamaindex.blocked",
                reason=decision.reason,
                policy_ids=decision.matched_policy_ids,
            )
            raise PolicyViolationError(
                message=decision.reason or "Request blocked by CyberArmor policy",
                decision=decision,
                request_id=request_id,
            )

        if decision.decision_type == DecisionType.REDACT and decision.redacted_messages:
            # Replace prompt with redacted content
            redacted_prompt = "\n".join(
                m.get("content", "") for m in decision.redacted_messages
            )
            if args:
                args = (redacted_prompt,) + args[1:]
            else:
                kwargs = dict(kwargs)
                kwargs["prompt"] = redacted_prompt

        # ---- Delegate --------------------------------------------------
        start_ts = time.monotonic()
        try:
            result = original_fn(self_llm, *args, **kwargs)
        except Exception as exc:
            audit.emit_error(
                request_id=request_id,
                provider="llamaindex",
                model=model,
                error=str(exc),
                duration_ms=int((time.monotonic() - start_ts) * 1000),
            )
            raise

        duration_ms = int((time.monotonic() - start_ts) * 1000)

        # ---- Audit event ----------------------------------------------
        audit.emit_completion(
            request_id=request_id,
            provider="llamaindex",
            model=model,
            prompt_tokens=None,
            completion_tokens=None,
            duration_ms=duration_ms,
            decision_type=decision.decision_type.value,
            matched_policy_ids=decision.matched_policy_ids,
        )

        log.info("cyberarmor.llamaindex.success", duration_ms=duration_ms)
        return result

    return wrapper


def _make_async_wrapper(
    original_fn: Callable,
    method_name: str,
    enforcer: PolicyEnforcer,
    audit: AuditEmitter,
) -> Callable:
    """
    Return an async wrapper around ``original_fn`` that enforces CyberArmor
    policy before the awaited call and emits an audit event after.
    """

    @functools.wraps(original_fn)
    async def async_wrapper(self_llm: Any, *args: Any, **kwargs: Any) -> Any:
        request_id = str(uuid.uuid4())
        prompt = _extract_prompt(args, kwargs)
        messages = _build_messages(prompt)

        model = (
            getattr(self_llm, "model", None)
            or getattr(self_llm, "_model_name", None)
            or type(self_llm).__name__
        )

        log = logger.bind(
            request_id=request_id,
            model=model,
            method=method_name,
            provider="llamaindex",
        )
        log.info("cyberarmor.llamaindex.async_request", prompt_length=len(prompt))

        policy_request = {
            "request_id": request_id,
            "provider": "llamaindex",
            "model": model,
            "messages": messages,
            "parameters": {k: v for k, v in kwargs.items() if k != "prompt"},
        }

        decision = enforcer.evaluate(policy_request)

        if decision.decision_type == DecisionType.BLOCK:
            raise PolicyViolationError(
                message=decision.reason or "Request blocked by CyberArmor policy",
                decision=decision,
                request_id=request_id,
            )

        if decision.decision_type == DecisionType.REDACT and decision.redacted_messages:
            redacted_prompt = "\n".join(
                m.get("content", "") for m in decision.redacted_messages
            )
            if args:
                args = (redacted_prompt,) + args[1:]
            else:
                kwargs = dict(kwargs)
                kwargs["prompt"] = redacted_prompt

        start_ts = time.monotonic()
        try:
            result = await original_fn(self_llm, *args, **kwargs)
        except Exception as exc:
            audit.emit_error(
                request_id=request_id,
                provider="llamaindex",
                model=model,
                error=str(exc),
                duration_ms=int((time.monotonic() - start_ts) * 1000),
            )
            raise

        duration_ms = int((time.monotonic() - start_ts) * 1000)

        audit.emit_completion(
            request_id=request_id,
            provider="llamaindex",
            model=model,
            prompt_tokens=None,
            completion_tokens=None,
            duration_ms=duration_ms,
            decision_type=decision.decision_type.value,
            matched_policy_ids=decision.matched_policy_ids,
        )

        log.info("cyberarmor.llamaindex.async_success", duration_ms=duration_ms)
        return result

    return async_wrapper


class CyberArmorInstrumentation:
    """
    Monkey-patches ``llama_index.core.llms.LLM`` to enforce CyberArmor
    policy on every ``complete`` and ``acomplete`` invocation.

    This is a **class-level patch**: once applied, *all* LlamaIndex LLM
    instances are covered because the patch targets the base class methods.
    To patch only a specific instance, pass it as the ``client`` argument.

    Example::

        # Patch globally
        CyberArmorInstrumentation.patch_all()

        # Patch a single instance
        from llama_index.llms.openai import OpenAI as LlamaOpenAI
        llm = LlamaOpenAI(model="gpt-4o")
        CyberArmorInstrumentation.patch_all(llm)
    """

    _patched_classes: set = set()
    _patched_instances: set = set()

    @classmethod
    def patch_all(
        cls,
        client: Optional[Any] = None,
        *,
        cyberarmor_client: Optional[CyberArmorClient] = None,
    ) -> None:
        """
        Apply CyberArmor instrumentation to LlamaIndex LLM(s).

        Args:
            client: A specific LlamaIndex LLM instance to patch.  If
                ``None``, the ``llama_index.core.llms.LLM`` base class is
                patched so that all instances are covered.
            cyberarmor_client: Optional existing
                :class:`~cyberarmor.client.CyberArmorClient`.  A default
                client is constructed from environment variables if omitted.
        """
        if cyberarmor_client is None:
            cyberarmor_client = CyberArmorClient()

        enforcer: PolicyEnforcer = cyberarmor_client.policy
        audit: AuditEmitter = cyberarmor_client.audit

        if client is not None:
            cls._patch_instance(client, enforcer=enforcer, audit=audit)
        else:
            cls._patch_base_class(enforcer=enforcer, audit=audit)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @classmethod
    def _patch_base_class(
        cls,
        *,
        enforcer: PolicyEnforcer,
        audit: AuditEmitter,
    ) -> None:
        """Patch the LlamaIndex base ``LLM`` class."""
        try:
            from llama_index.core.llms import LLM  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "llama-index-core is required for CyberArmorInstrumentation. "
                "Install it with: pip install cyberarmor-sdk[llamaindex]"
            ) from exc

        if id(LLM) in cls._patched_classes:
            logger.warning(
                "cyberarmor.llamaindex.already_patched",
                target="llama_index.core.llms.LLM",
            )
            return

        cls._patch_methods(LLM, enforcer=enforcer, audit=audit)
        cls._patched_classes.add(id(LLM))

        logger.info(
            "cyberarmor.llamaindex.patched",
            target="llama_index.core.llms.LLM",
        )

    @classmethod
    def _patch_instance(
        cls,
        instance: Any,
        *,
        enforcer: PolicyEnforcer,
        audit: AuditEmitter,
    ) -> None:
        """Patch a specific LLM instance by binding wrapped methods."""
        instance_id = id(instance)
        if instance_id in cls._patched_instances:
            logger.warning(
                "cyberarmor.llamaindex.instance_already_patched",
                instance_type=type(instance).__name__,
            )
            return

        for method_name in ("complete", "acomplete"):
            original = getattr(type(instance), method_name, None)
            if original is None:
                continue

            if asyncio.iscoroutinefunction(original):
                wrapped = _make_async_wrapper(
                    original, method_name, enforcer, audit
                )
            else:
                wrapped = _make_sync_wrapper(
                    original, method_name, enforcer, audit
                )

            # Bind as an instance method
            import types

            setattr(instance, method_name, types.MethodType(wrapped, instance))

        cls._patched_instances.add(instance_id)
        logger.info(
            "cyberarmor.llamaindex.instance_patched",
            instance_type=type(instance).__name__,
        )

    @classmethod
    def _patch_methods(
        cls,
        target_class: type,
        *,
        enforcer: PolicyEnforcer,
        audit: AuditEmitter,
    ) -> None:
        """Replace ``complete`` and ``acomplete`` on ``target_class``."""
        for method_name in ("complete", "acomplete"):
            original = getattr(target_class, method_name, None)
            if original is None:
                continue

            if getattr(original, _CYBERARMOR_PATCHED_ATTR, False):
                continue

            if asyncio.iscoroutinefunction(original):
                wrapped = _make_async_wrapper(
                    original, method_name, enforcer, audit
                )
            else:
                wrapped = _make_sync_wrapper(
                    original, method_name, enforcer, audit
                )

            setattr(wrapped, _CYBERARMOR_PATCHED_ATTR, True)
            setattr(target_class, method_name, wrapped)

    @classmethod
    def unpatch_all(cls) -> None:
        """
        Remove CyberArmor patches from ``llama_index.core.llms.LLM``.

        This restores the original ``complete`` and ``acomplete`` methods.
        Useful in test teardowns.
        """
        try:
            from llama_index.core.llms import LLM  # type: ignore[import]
        except ImportError:
            return

        for method_name in ("complete", "acomplete"):
            method = getattr(LLM, method_name, None)
            if method and getattr(method, _CYBERARMOR_PATCHED_ATTR, False):
                original = getattr(method, "__wrapped__", None)
                if original:
                    setattr(LLM, method_name, original)

        cls._patched_classes.discard(id(LLM))
        logger.info("cyberarmor.llamaindex.unpatched")
