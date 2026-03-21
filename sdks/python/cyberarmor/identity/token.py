"""
TokenManager — JWT issuance, validation, refresh, and caching for AI agent tokens.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


class _CachedToken:
    """Thread-safe cached token entry."""
    __slots__ = ("access_token", "refresh_token", "expires_at", "agent_id")

    def __init__(
        self,
        access_token: str,
        expires_at: float,
        agent_id: str,
        refresh_token: Optional[str] = None,
    ) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = expires_at
        self.agent_id = agent_id

    def is_valid(self, buffer_seconds: float = 30.0) -> bool:
        return time.time() < (self.expires_at - buffer_seconds)


class TokenManager:
    """
    Manages short-lived JWT tokens for AI agent identities.

    Features
    --------
    - Automatic token refresh with configurable buffer.
    - Per-agent in-memory cache (thread-safe).
    - Explicit revocation.
    - JWKS-based offline verification (optional).

    Usage
    -----
    tm = TokenManager(
        api_url="https://api.cyberarmor.ai/v1",
        api_key="sk-...",
        tenant_id="acme",
    )
    token = tm.get_token(agent_id="agent-abc")
    claims = tm.verify_token(token)
    """

    def __init__(
        self,
        api_url: str,
        api_key: Optional[str] = None,
        tenant_id: Optional[str] = None,
        token_ttl: int = 3600,
        refresh_buffer: float = 60.0,
        max_retries: int = 3,
        timeout: float = 10.0,
        verify_ssl: bool = True,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._api_key = api_key
        self._tenant_id = tenant_id
        self._token_ttl = token_ttl
        self._refresh_buffer = refresh_buffer
        self._max_retries = max_retries
        self._timeout = timeout
        self._verify_ssl = verify_ssl

        self._cache: Dict[str, _CachedToken] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_token(self, agent_id: str, force_refresh: bool = False) -> str:
        """
        Return a valid access token for *agent_id*, refreshing if necessary.

        Raises
        ------
        ConnectionError
            If the token service is unreachable after max_retries.
        PermissionError
            If the API key is rejected (401/403).
        """
        with self._lock:
            cached = self._cache.get(agent_id)
            if not force_refresh and cached and cached.is_valid(self._refresh_buffer):
                return cached.access_token

        token_data = self._fetch_token(agent_id)

        entry = _CachedToken(
            access_token=token_data["access_token"],
            expires_at=time.time() + token_data.get("expires_in", self._token_ttl),
            agent_id=agent_id,
            refresh_token=token_data.get("refresh_token"),
        )
        with self._lock:
            self._cache[agent_id] = entry

        return entry.access_token

    def revoke_token(self, agent_id: str) -> bool:
        """
        Revoke the cached token for *agent_id* and notify the server.

        Returns True if revocation was acknowledged by the server.
        """
        with self._lock:
            cached = self._cache.pop(agent_id, None)

        if not cached:
            logger.debug("No cached token to revoke for agent_id=%s", agent_id)
            return True

        try:
            with httpx.Client(timeout=self._timeout, verify=self._verify_ssl) as client:
                resp = client.post(
                    f"{self._api_url}/auth/revoke",
                    json={
                        "token": cached.access_token,
                        "agent_id": agent_id,
                        "tenant_id": self._tenant_id,
                    },
                    headers=self._build_headers(),
                )
                resp.raise_for_status()
                return True
        except Exception as exc:
            logger.warning("Token revocation failed for agent_id=%s: %s", agent_id, exc)
            return False

    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify *token* by calling the introspection endpoint.

        Returns the token claims dict on success.
        Raises ValueError if the token is inactive or invalid.
        """
        try:
            with httpx.Client(timeout=self._timeout, verify=self._verify_ssl) as client:
                resp = client.post(
                    f"{self._api_url}/auth/introspect",
                    json={"token": token, "tenant_id": self._tenant_id},
                    headers=self._build_headers(),
                )
                resp.raise_for_status()
                data = resp.json()

            if not data.get("active", False):
                raise ValueError("Token is not active or has been revoked.")

            return data
        except httpx.HTTPStatusError as exc:
            raise ValueError(f"Token introspection failed: {exc.response.text}") from exc

    def invalidate_all(self) -> None:
        """Clear the in-memory token cache (does not revoke server-side)."""
        with self._lock:
            self._cache.clear()
        logger.debug("TokenManager cache cleared.")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _fetch_token(self, agent_id: str) -> Dict[str, Any]:
        """
        Request a new token from the agent-identity service.
        """
        payload: Dict[str, Any] = {
            "agent_id": agent_id,
            "tenant_id": self._tenant_id,
            "grant_type": "agent_credentials",
        }
        if self._api_key:
            payload["api_key"] = self._api_key

        last_exc: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            try:
                with httpx.Client(timeout=self._timeout, verify=self._verify_ssl) as client:
                    resp = client.post(
                        f"{self._api_url}/auth/token",
                        json=payload,
                        headers=self._build_headers(),
                    )
                    resp.raise_for_status()
                    return resp.json()
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in (401, 403):
                    raise PermissionError(
                        f"Token fetch rejected for agent_id={agent_id}: {exc.response.text}"
                    ) from exc
                last_exc = exc
            except httpx.RequestError as exc:
                last_exc = exc

            if attempt < self._max_retries:
                wait = 2 ** attempt * 0.5
                logger.warning(
                    "Token fetch attempt %d/%d failed; retrying in %.1fs: %s",
                    attempt + 1, self._max_retries + 1, wait, last_exc,
                )
                time.sleep(wait)

        raise ConnectionError(
            f"Token fetch for agent_id={agent_id} failed after "
            f"{self._max_retries + 1} attempts: {last_exc}"
        )

    def _build_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "X-SDK-Version": "1.0.0",
        }
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        if self._tenant_id:
            headers["X-Tenant-ID"] = self._tenant_id
        return headers

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def cache_stats(self) -> Dict[str, Any]:
        """Return a snapshot of the token cache for observability."""
        with self._lock:
            return {
                "cached_agents": list(self._cache.keys()),
                "total": len(self._cache),
                "valid": sum(1 for t in self._cache.values() if t.is_valid(self._refresh_buffer)),
            }

    def __repr__(self) -> str:
        return (
            f"TokenManager(api_url={self._api_url!r}, "
            f"tenant_id={self._tenant_id!r}, "
            f"cached_agents={len(self._cache)})"
        )
