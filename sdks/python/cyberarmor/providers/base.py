"""
BaseProviderInterceptor — shared pre/post call logic for all AI provider wrappers.

Every concrete provider (OpenAI, Anthropic, Google, Bedrock, …) extends this
base class and calls _pre_call_check() before forwarding to the underlying SDK
and _post_call_emit() after receiving the response.
"""
from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional

from ..client import CyberArmorClient
from ..config import CyberArmorConfig
from ..policy.decisions import Decision, DecisionType, PolicyViolationError

logger = logging.getLogger(__name__)


class BaseProviderInterceptor:
    """
    Mixin/base class for AI provider interceptors.

    Sub-classes must call super().__init__(cyberarmor_client=...) or
    pass cyberarmor_config / cyberarmor_api_key during construction.

    Key methods to call in provider wrappers
    -----------------------------------------
    _pre_call_check(prompt, model, provider, metadata)
        -> raises PolicyViolationError or returns Decision
    _post_call_emit(prompt, response_text, model, provider, decision, latency_ms)
        -> emits audit event asynchronously (best-effort)
    """

    def __init__(
        self,
        cyberarmor_client: Optional[CyberArmorClient] = None,
        cyberarmor_config: Optional[CyberArmorConfig] = None,
        cyberarmor_api_key: Optional[str] = None,
        cyberarmor_api_url: Optional[str] = None,
        cyberarmor_tenant_id: Optional[str] = None,
        cyberarmor_agent_id: Optional[str] = None,
        raise_on_deny: bool = True,
        audit_responses: bool = True,
        **kwargs: Any,
    ) -> None:
        if cyberarmor_client is not None:
            self._ca_client = cyberarmor_client
        elif cyberarmor_config is not None:
            self._ca_client = CyberArmorClient(config=cyberarmor_config)
        else:
            # Build config from explicit args or environment
            config = CyberArmorConfig.from_env()
            if cyberarmor_api_key:
                config.api_key = cyberarmor_api_key
            if cyberarmor_api_url:
                config.api_url = cyberarmor_api_url
            if cyberarmor_tenant_id:
                config.tenant_id = cyberarmor_tenant_id
            if cyberarmor_agent_id:
                config.agent_id = cyberarmor_agent_id
            self._ca_client = CyberArmorClient(config=config)

        self._raise_on_deny = raise_on_deny
        self._audit_responses = audit_responses

    # ------------------------------------------------------------------
    # Pre-call
    # ------------------------------------------------------------------

    def _pre_call_check(
        self,
        prompt: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        raise_on_deny: Optional[bool] = None,
    ) -> Decision:
        """
        Evaluate the outbound prompt against CyberArmor policies.

        Returns the Decision (allows caller to inspect redacted prompt, etc.).
        Raises PolicyViolationError if the decision is DENY and raise_on_deny is True.
        """
        should_raise = raise_on_deny if raise_on_deny is not None else self._raise_on_deny

        try:
            decision = self._ca_client.evaluate_policy(
                prompt=prompt,
                model=model,
                provider=provider,
                metadata=metadata or {},
                raise_on_deny=should_raise,
            )
        except PolicyViolationError:
            raise
        except Exception as exc:
            logger.warning(
                "CyberArmor pre-call check failed (non-fatal): %s. "
                "Proceeding with AUDIT decision.", exc
            )
            decision = Decision(
                decision=DecisionType.AUDIT,
                risk_score=0.0,
                reasons=[f"Pre-call check error: {exc}"],
            )

        if decision.requires_redaction() and decision.redacted_prompt:
            logger.info(
                "CyberArmor DLP: prompt redacted before forwarding to %s.", provider
            )

        return decision

    # ------------------------------------------------------------------
    # Post-call
    # ------------------------------------------------------------------

    def _post_call_emit(
        self,
        prompt: Optional[str] = None,
        response_text: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        decision: Optional[Decision] = None,
        latency_ms: float = 0.0,
        error: Optional[str] = None,
    ) -> None:
        """
        Emit an audit event for the completed AI call (best-effort, non-blocking).
        """
        try:
            payload: Dict[str, Any] = {
                "provider": provider,
                "model": model,
                "latency_ms": round(latency_ms, 2),
                "error": error,
            }

            if decision:
                payload["policy_decision"] = decision.decision.value
                payload["risk_score"] = decision.risk_score
                payload["matched_policies"] = decision.matched_policies

            if prompt:
                payload["prompt_hash"] = hashlib.sha256(
                    prompt.encode("utf-8", errors="replace")
                ).hexdigest()

            if self._audit_responses and response_text:
                payload["response_hash"] = hashlib.sha256(
                    response_text.encode("utf-8", errors="replace")
                ).hexdigest()
                payload["response_length"] = len(response_text)

            event_type = "ai_call_error" if error else "ai_call_completed"
            self._ca_client.emit_event(event_type, payload=payload)

        except Exception as exc:
            logger.debug("Post-call audit event emission failed (non-fatal): %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_prompt_text(self, messages: List[Dict[str, Any]]) -> str:
        """
        Extract a single concatenated text string from a messages list
        (OpenAI / Anthropic format).
        """
        parts: List[str] = []
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                # Multi-modal content blocks
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
        return " ".join(parts)

    def _ca_close(self) -> None:
        """Close the underlying CyberArmor client if owned by this interceptor."""
        try:
            self._ca_client.close()
        except Exception:
            pass

    @property
    def cyberarmor_client(self) -> CyberArmorClient:
        """Direct access to the underlying CyberArmorClient."""
        return self._ca_client
