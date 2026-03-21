"""
PolicyEnforcer — thin client wrapper that evaluates requests against
CyberArmor policies, with optional local fallback evaluation.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from .decisions import Decision, DecisionType, PolicyViolationError

logger = logging.getLogger(__name__)


class PolicyEnforcer:
    """
    Evaluates AI requests against CyberArmor policies.

    Supports three modes:
    1. Remote-only  — delegates all evaluation to the policy service.
    2. Local-only   — loads a JSON policy file and evaluates in-process.
    3. Hybrid       — tries remote, falls back to local on failure.

    Usage (sync)
    ------------
    enforcer = PolicyEnforcer(
        api_url="https://api.cyberarmor.ai/v1",
        api_key="sk-...",
        tenant_id="acme",
        local_policy_path="/etc/cyberarmor/policy.json",  # optional fallback
    )
    decision = enforcer.evaluate(prompt="Hello", model="gpt-4o")
    enforcer.enforce(decision)   # raises PolicyViolationError if denied

    Usage (async)
    -------------
    decision = await enforcer.evaluate_async(prompt="Hello", model="gpt-4o")
    """

    def __init__(
        self,
        api_url: str,
        api_key: Optional[str] = None,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        environment: str = "production",
        local_policy_path: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 3,
        verify_ssl: bool = True,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._api_key = api_key
        self._tenant_id = tenant_id
        self._agent_id = agent_id
        self._environment = environment
        self._timeout = timeout
        self._max_retries = max_retries
        self._verify_ssl = verify_ssl

        # Local policy rules loaded from disk (list of dicts)
        self._local_rules: List[Dict[str, Any]] = []
        if local_policy_path:
            self._load_local_policy(local_policy_path)

    # ------------------------------------------------------------------
    # Sync evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Decision:
        """
        Evaluate *prompt* (and optional *response*) against active policies.

        Falls back to local evaluation when the remote service is unavailable.
        """
        payload = self._build_payload(prompt, response, model, provider, metadata, **kwargs)

        # Try remote first
        remote_decision = self._remote_evaluate(payload)
        if remote_decision is not None:
            return remote_decision

        # Local fallback
        logger.info("Remote policy evaluation unavailable; using local fallback.")
        return self._local_evaluate(payload)

    # ------------------------------------------------------------------
    # Async evaluation
    # ------------------------------------------------------------------

    async def evaluate_async(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Decision:
        """Async variant of evaluate()."""
        payload = self._build_payload(prompt, response, model, provider, metadata, **kwargs)

        remote_decision = await self._remote_evaluate_async(payload)
        if remote_decision is not None:
            return remote_decision

        logger.info("Remote async policy evaluation unavailable; using local fallback.")
        return self._local_evaluate(payload)

    # ------------------------------------------------------------------
    # Enforce (convenience)
    # ------------------------------------------------------------------

    def enforce(self, decision: Decision) -> Decision:
        """
        Enforce a decision: raise PolicyViolationError if denied.

        Returns *decision* unchanged on success so callers can chain:
            decision = enforcer.enforce(enforcer.evaluate(prompt=...))
        """
        if decision.is_denied():
            raise PolicyViolationError(decision)
        return decision

    # ------------------------------------------------------------------
    # Local evaluation (in-process fallback)
    # ------------------------------------------------------------------

    def _local_evaluate(self, payload: Dict[str, Any]) -> Decision:
        """
        Minimal in-process policy evaluation using loaded local rules.

        Applies rules in order; first matching rule wins.
        Falls back to AUDIT if no rules are configured.
        """
        if not self._local_rules:
            return Decision(
                decision=DecisionType.AUDIT,
                risk_score=0.0,
                reasons=["Local policy fallback: no rules configured; defaulting to audit."],
            )

        prompt_text = payload.get("prompt", "") or ""
        model = (payload.get("model") or "").lower()
        provider = (payload.get("provider") or "").lower()

        for rule in self._local_rules:
            if not rule.get("enabled", True):
                continue

            matched = False

            # Keyword block list
            blocked_keywords = rule.get("blocked_keywords", [])
            if blocked_keywords and any(kw.lower() in prompt_text.lower() for kw in blocked_keywords):
                matched = True

            # Model block list
            blocked_models = rule.get("blocked_models", [])
            if blocked_models and any(m.lower() in model for m in blocked_models):
                matched = True

            # Provider block list
            blocked_providers = rule.get("blocked_providers", [])
            if blocked_providers and provider in [p.lower() for p in blocked_providers]:
                matched = True

            if matched:
                action = rule.get("action", "deny")
                try:
                    decision_type = DecisionType(action)
                except ValueError:
                    decision_type = DecisionType.DENY

                return Decision(
                    decision=decision_type,
                    risk_score=float(rule.get("risk_score", 1.0)),
                    reasons=[f"[local:{rule.get('rule_id', 'unknown')}] {rule.get('description', '')}"],
                    matched_policies=[rule.get("rule_id", "local-rule")],
                )

        # No rule matched
        return Decision(
            decision=DecisionType.ALLOW,
            risk_score=0.0,
            reasons=["Local policy evaluation: no rules matched; request allowed."],
        )

    # ------------------------------------------------------------------
    # Remote evaluation helpers
    # ------------------------------------------------------------------

    def _remote_evaluate(self, payload: Dict[str, Any]) -> Optional[Decision]:
        """
        Try to evaluate against the remote policy service.
        Returns None on connection failure (triggers fallback).
        """
        last_exc: Optional[Exception] = None

        for attempt in range(self._max_retries + 1):
            try:
                with httpx.Client(
                    timeout=self._timeout,
                    verify=self._verify_ssl,
                ) as client:
                    resp = client.post(
                        f"{self._api_url}/policy/evaluate",
                        json=payload,
                        headers=self._build_headers(),
                    )
                    resp.raise_for_status()
                    return Decision.from_api_response(resp.json())
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in (400, 401, 403, 422):
                    # Non-retriable — raise immediately
                    raise
                last_exc = exc
            except httpx.RequestError as exc:
                last_exc = exc

            if attempt < self._max_retries:
                wait = 2 ** attempt * 0.5
                logger.debug("Policy evaluation retry %d/%d in %.1fs: %s",
                             attempt + 1, self._max_retries, wait, last_exc)
                time.sleep(wait)

        logger.warning("Remote policy evaluation failed after %d attempts: %s",
                       self._max_retries + 1, last_exc)
        return None

    async def _remote_evaluate_async(self, payload: Dict[str, Any]) -> Optional[Decision]:
        """Async variant of _remote_evaluate."""
        last_exc: Optional[Exception] = None

        for attempt in range(self._max_retries + 1):
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout,
                    verify=self._verify_ssl,
                ) as client:
                    resp = await client.post(
                        f"{self._api_url}/policy/evaluate",
                        json=payload,
                        headers=self._build_headers(),
                    )
                    resp.raise_for_status()
                    return Decision.from_api_response(resp.json())
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in (400, 401, 403, 422):
                    raise
                last_exc = exc
            except httpx.RequestError as exc:
                last_exc = exc

            if attempt < self._max_retries:
                await asyncio.sleep(2 ** attempt * 0.5)

        logger.warning("Async remote policy evaluation failed after %d attempts: %s",
                       self._max_retries + 1, last_exc)
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_payload(
        self,
        prompt: Optional[str],
        response: Optional[str],
        model: Optional[str],
        provider: Optional[str],
        metadata: Optional[Dict[str, Any]],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "agent_id": self._agent_id,
            "tenant_id": self._tenant_id,
            "environment": self._environment,
            "model": model,
            "provider": provider,
            "metadata": metadata or {},
        }
        if prompt is not None:
            payload["prompt"] = prompt
        if response is not None:
            payload["response"] = response
        payload.update(kwargs)
        return payload

    def _build_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "X-SDK-Version": "1.0.0",
        }
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        if self._tenant_id:
            headers["X-Tenant-ID"] = self._tenant_id
        if self._agent_id:
            headers["X-Agent-ID"] = self._agent_id
        return headers

    def _load_local_policy(self, path: str) -> None:
        """Load and parse a local policy JSON file."""
        policy_path = Path(path)
        if not policy_path.exists():
            logger.warning("Local policy file not found: %s", path)
            return
        try:
            with policy_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                self._local_rules = data
            elif isinstance(data, dict):
                self._local_rules = data.get("rules", [])
            logger.info("Loaded %d local policy rules from %s", len(self._local_rules), path)
        except Exception as exc:
            logger.error("Failed to load local policy from %s: %s", path, exc)

    def __repr__(self) -> str:
        return (
            f"PolicyEnforcer("
            f"api_url={self._api_url!r}, "
            f"tenant_id={self._tenant_id!r}, "
            f"local_rules={len(self._local_rules)})"
        )
