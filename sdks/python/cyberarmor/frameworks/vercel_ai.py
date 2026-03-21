"""
CyberArmor Vercel AI Integration
=================================
Provides a lightweight guard wrapper for Vercel AI style chat calls so
policy can be evaluated before model invocation and audit can be emitted
after completion.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from cyberarmor.client import CyberArmorClient
from cyberarmor.policy.decisions import DecisionType, PolicyViolationError


class CyberArmorVercelAI:
    """Framework-agnostic wrapper for Vercel AI style chat handlers."""

    def __init__(self, client: Optional[CyberArmorClient] = None) -> None:
        self._client = client or CyberArmorClient()

    def guard_chat(
        self,
        handler: Callable[[List[Dict[str, Any]], Dict[str, Any]], Dict[str, Any]],
        messages: List[Dict[str, Any]],
        *,
        model: str = "unknown",
        provider: str = "vercel-ai",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        user_text = "\n".join(
            str(m.get("content", ""))
            for m in messages
            if isinstance(m, dict) and m.get("role") == "user"
        )
        decision = self._client.policy.evaluate(
            {
                "provider": provider,
                "model": model,
                "messages": messages,
                "metadata": metadata or {},
            }
        )
        if decision.decision_type == DecisionType.BLOCK:
            raise PolicyViolationError(
                message=decision.reason or "Request blocked by CyberArmor policy",
                decision=decision,
            )

        if decision.decision_type == DecisionType.REDACT and decision.redacted_messages:
            redacted = decision.redacted_messages
        else:
            redacted = messages

        out = handler(redacted, metadata or {})
        self._client.audit.emit_completion(
            request_id=None,
            provider=provider,
            model=model,
            prompt_tokens=None,
            completion_tokens=None,
            duration_ms=0,
            decision_type=decision.decision_type.value,
            matched_policy_ids=decision.matched_policy_ids,
        )
        _ = user_text  # kept for compatibility/debug parity with other wrappers
        return out
