"""
CyberArmorClient — primary entry point for the CyberArmor Python SDK.

Handles authentication, policy evaluation, and audit event emission.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from .config import CyberArmorConfig
from .policy.decisions import Decision, DecisionType, PolicyViolationError

logger = logging.getLogger(__name__)


class CyberArmorClient:
    """
    Thread-safe client for the CyberArmor AI Identity Control Plane.

    Typical usage
    -------------
    client = CyberArmorClient(api_key="...", tenant_id="acme", agent_id="my-agent")
    decision = client.evaluate_policy(prompt="...", model="gpt-4o")
    if decision.is_denied():
        raise PolicyViolationError(decision)

    Context manager (sync)
    ----------------------
    with CyberArmorClient.from_env() as client:
        decision = client.evaluate_policy(prompt="Hello")

    Async context manager
    ---------------------
    async with client.async_session() as ac:
        decision = await ac.evaluate_policy_async(prompt="Hello")
    """

    _DEFAULT_HEADERS = {
        "Content-Type": "application/json",
        "X-SDK-Version": "1.0.0",
        "X-SDK-Language": "python",
    }

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        environment: Optional[str] = None,
        config: Optional[CyberArmorConfig] = None,
        **kwargs: Any,
    ) -> None:
        if config is not None:
            self._config = config
        else:
            self._config = CyberArmorConfig.from_env()
            # Explicit constructor args override env
            if api_key:
                self._config.api_key = api_key
            if api_url:
                self._config.api_url = api_url
            if tenant_id:
                self._config.tenant_id = tenant_id
            if agent_id:
                self._config.agent_id = agent_id
            if environment:
                self._config.environment = environment
            # Accept any extra kwargs as config overrides
            for k, v in kwargs.items():
                if hasattr(self._config, k):
                    setattr(self._config, k, v)

        self._config.validate()

        # Token state
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0

        # Synchronous HTTP client (lazy init)
        self._sync_client: Optional[httpx.Client] = None

        logging.basicConfig(level=getattr(logging, self._config.log_level, logging.WARNING))

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "CyberArmorClient":
        """Create a client from environment variables."""
        return cls(config=CyberArmorConfig.from_env())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_sync_client(self) -> httpx.Client:
        if self._sync_client is None or self._sync_client.is_closed:
            self._sync_client = httpx.Client(
                base_url=self._config.api_url,
                timeout=self._config.timeout_seconds,
                verify=self._config.verify_ssl,
                headers=self._DEFAULT_HEADERS,
            )
        return self._sync_client

    def _auth_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
        elif self._config.api_key:
            headers["X-API-Key"] = self._config.api_key
        if self._config.tenant_id:
            headers["X-Tenant-ID"] = self._config.tenant_id
        if self._config.agent_id:
            headers["X-Agent-ID"] = self._config.agent_id
        return headers

    def _is_token_valid(self) -> bool:
        return (
            self._access_token is not None
            and time.time() < self._token_expires_at - 30  # 30-second buffer
        )

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def get_token(self) -> str:
        """
        Return a valid Bearer token, refreshing if necessary (sync).
        """
        if not self._is_token_valid():
            self._refresh_token()
        return self._access_token  # type: ignore[return-value]

    def _refresh_token(self) -> None:
        """
        Exchange the API key for a short-lived Bearer token (sync).
        Retries up to config.max_retries times on transient errors.
        """
        if not self._config.api_key:
            logger.debug("No API key; skipping token refresh.")
            return

        client = self._get_sync_client()
        payload = {
            "api_key": self._config.api_key,
            "tenant_id": self._config.tenant_id,
            "agent_id": self._config.agent_id,
        }

        last_exc: Optional[Exception] = None
        for attempt in range(self._config.max_retries + 1):
            try:
                resp = client.post("/auth/token", json=payload)
                resp.raise_for_status()
                data = resp.json()
                self._access_token = data["access_token"]
                self._token_expires_at = time.time() + data.get("expires_in", self._config.token_ttl)
                logger.debug("Token refreshed; expires_in=%s", data.get("expires_in"))
                return
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in (401, 403):
                    raise PermissionError(
                        f"CyberArmor authentication failed: {exc.response.text}"
                    ) from exc
                last_exc = exc
            except httpx.RequestError as exc:
                last_exc = exc

            if attempt < self._config.max_retries:
                wait = 2 ** attempt * 0.5
                logger.warning("Token refresh attempt %d failed; retrying in %.1fs", attempt + 1, wait)
                time.sleep(wait)

        raise ConnectionError(
            f"CyberArmor token refresh failed after {self._config.max_retries + 1} attempts: {last_exc}"
        )

    async def _refresh_token_async(self) -> None:
        """Exchange the API key for a Bearer token (async)."""
        if not self._config.api_key:
            return

        payload = {
            "api_key": self._config.api_key,
            "tenant_id": self._config.tenant_id,
            "agent_id": self._config.agent_id,
        }

        last_exc: Optional[Exception] = None
        async with httpx.AsyncClient(
            base_url=self._config.api_url,
            timeout=self._config.timeout_seconds,
            verify=self._config.verify_ssl,
            headers=self._DEFAULT_HEADERS,
        ) as ac:
            for attempt in range(self._config.max_retries + 1):
                try:
                    resp = await ac.post("/auth/token", json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    self._access_token = data["access_token"]
                    self._token_expires_at = time.time() + data.get("expires_in", self._config.token_ttl)
                    return
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code in (401, 403):
                        raise PermissionError(
                            f"CyberArmor authentication failed: {exc.response.text}"
                        ) from exc
                    last_exc = exc
                except httpx.RequestError as exc:
                    last_exc = exc

                if attempt < self._config.max_retries:
                    await asyncio.sleep(2 ** attempt * 0.5)

        raise ConnectionError(
            f"CyberArmor async token refresh failed after {self._config.max_retries + 1} attempts: {last_exc}"
        )

    # ------------------------------------------------------------------
    # Policy evaluation
    # ------------------------------------------------------------------

    def evaluate_policy(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        raise_on_deny: bool = False,
        **kwargs: Any,
    ) -> Decision:
        """
        Evaluate a policy decision synchronously.

        Parameters
        ----------
        prompt : str, optional
            The user or agent prompt to evaluate.
        response : str, optional
            The AI model response to evaluate (post-call).
        model : str, optional
            Model identifier (e.g., "gpt-4o").
        provider : str, optional
            Provider name (e.g., "openai").
        metadata : dict, optional
            Arbitrary extra context forwarded to the policy engine.
        raise_on_deny : bool
            If True, raise PolicyViolationError when the decision is DENY.

        Returns
        -------
        Decision
        """
        if not self._is_token_valid():
            try:
                self._refresh_token()
            except Exception as exc:
                logger.warning("Token refresh failed; proceeding in degraded mode: %s", exc)

        payload: Dict[str, Any] = {
            "agent_id": self._config.agent_id,
            "tenant_id": self._config.tenant_id,
            "environment": self._config.environment,
            "model": model,
            "provider": provider,
            "metadata": metadata or {},
        }
        if prompt is not None:
            payload["prompt_hash"] = self.hash_prompt(prompt)
            if self._config.dlp_enabled:
                payload["prompt"] = prompt
        if response is not None:
            payload["response"] = response

        payload.update(kwargs)

        client = self._get_sync_client()
        last_exc: Optional[Exception] = None

        for attempt in range(self._config.max_retries + 1):
            try:
                resp = client.post(
                    "/policy/evaluate",
                    json=payload,
                    headers=self._auth_headers(),
                )
                resp.raise_for_status()
                decision = Decision.from_api_response(resp.json())
                if raise_on_deny and decision.is_denied():
                    raise PolicyViolationError(decision)
                return decision
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in (400, 401, 403, 422):
                    raise
                last_exc = exc
            except httpx.RequestError as exc:
                last_exc = exc

            if attempt < self._config.max_retries:
                time.sleep(2 ** attempt * 0.5)

        logger.warning(
            "Policy evaluation failed after %d attempts; defaulting to AUDIT: %s",
            self._config.max_retries + 1, last_exc
        )
        return Decision(
            decision=DecisionType.AUDIT,
            risk_score=0.0,
            reasons=["Policy service unreachable; defaulting to audit."],
        )

    async def evaluate_policy_async(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        raise_on_deny: bool = False,
        **kwargs: Any,
    ) -> Decision:
        """Async variant of evaluate_policy."""
        if not self._is_token_valid():
            try:
                await self._refresh_token_async()
            except Exception as exc:
                logger.warning("Async token refresh failed; proceeding in degraded mode: %s", exc)

        payload: Dict[str, Any] = {
            "agent_id": self._config.agent_id,
            "tenant_id": self._config.tenant_id,
            "environment": self._config.environment,
            "model": model,
            "provider": provider,
            "metadata": metadata or {},
        }
        if prompt is not None:
            payload["prompt_hash"] = self.hash_prompt(prompt)
            if self._config.dlp_enabled:
                payload["prompt"] = prompt
        if response is not None:
            payload["response"] = response

        payload.update(kwargs)

        last_exc: Optional[Exception] = None
        async with httpx.AsyncClient(
            base_url=self._config.api_url,
            timeout=self._config.timeout_seconds,
            verify=self._config.verify_ssl,
            headers={**self._DEFAULT_HEADERS, **self._auth_headers()},
        ) as ac:
            for attempt in range(self._config.max_retries + 1):
                try:
                    resp = await ac.post("/policy/evaluate", json=payload)
                    resp.raise_for_status()
                    decision = Decision.from_api_response(resp.json())
                    if raise_on_deny and decision.is_denied():
                        raise PolicyViolationError(decision)
                    return decision
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code in (400, 401, 403, 422):
                        raise
                    last_exc = exc
                except httpx.RequestError as exc:
                    last_exc = exc

                if attempt < self._config.max_retries:
                    await asyncio.sleep(2 ** attempt * 0.5)

        logger.warning(
            "Async policy evaluation failed after %d attempts; defaulting to AUDIT: %s",
            self._config.max_retries + 1, last_exc
        )
        return Decision(
            decision=DecisionType.AUDIT,
            risk_score=0.0,
            reasons=["Policy service unreachable; defaulting to audit."],
        )

    # ------------------------------------------------------------------
    # Audit event emission
    # ------------------------------------------------------------------

    def emit_event(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
    ) -> bool:
        """
        Emit an audit event to the CyberArmor event pipeline.

        Returns True on success, False on non-fatal failure.
        """
        if not self._config.audit_enabled:
            return True

        body: Dict[str, Any] = {
            "event_type": event_type,
            "agent_id": agent_id or self._config.agent_id,
            "tenant_id": self._config.tenant_id,
            "environment": self._config.environment,
            "timestamp": time.time(),
            "payload": payload or {},
        }

        try:
            client = self._get_sync_client()
            resp = client.post(
                "/audit/events",
                json=body,
                headers=self._auth_headers(),
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.warning("Audit event emission failed (non-fatal): %s", exc)
            return False

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def hash_prompt(prompt: str) -> str:
        """
        Return a stable SHA-256 hex digest of *prompt*.

        Used for audit trails when DLP is disabled (avoid logging raw text).
        """
        return hashlib.sha256(prompt.encode("utf-8", errors="replace")).hexdigest()

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    @asynccontextmanager
    async def async_session(self) -> AsyncIterator["CyberArmorClient"]:
        """
        Async context manager yielding *self*.

        async with client.async_session() as c:
            await c.evaluate_policy_async(...)
        """
        try:
            yield self
        finally:
            await self._aclose()

    async def _aclose(self) -> None:
        """No persistent async resources to close (clients are per-request)."""
        pass

    # ------------------------------------------------------------------
    # Resource cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying synchronous HTTP client."""
        if self._sync_client and not self._sync_client.is_closed:
            self._sync_client.close()

    # ------------------------------------------------------------------
    # Sync context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "CyberArmorClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"CyberArmorClient("
            f"agent_id={self._config.agent_id!r}, "
            f"tenant_id={self._config.tenant_id!r}, "
            f"environment={self._config.environment!r}, "
            f"api_url={self._config.api_url!r})"
        )
