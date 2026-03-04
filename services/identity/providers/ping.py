"""Ping Identity (PingOne) identity provider.

Uses the PingOne Management API for user, group, and role operations.
Authenticates via OAuth 2.0 client credentials to obtain a management
access token.

Required environment variables:
    PING_ENV_ID        - PingOne environment ID.
    PING_CLIENT_ID     - OAuth 2.0 client ID with management permissions.
    PING_CLIENT_SECRET - Corresponding client secret.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

import httpx

from .base import AuthResult, IdentityProviderBase, ProviderType, UserInfo

logger = logging.getLogger("identity.providers.ping")

PINGONE_AUTH_BASE = "https://auth.pingone.com"
PINGONE_API_BASE = "https://api.pingone.com/v1"


class PingIdentityProvider(IdentityProviderBase):
    """Identity provider backed by PingOne."""

    provider_type = ProviderType.PING

    def __init__(
        self,
        env_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> None:
        self.env_id = env_id or os.getenv("PING_ENV_ID", "")
        self.client_id = client_id or os.getenv("PING_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("PING_CLIENT_SECRET", "")

        if not all([self.env_id, self.client_id, self.client_secret]):
            logger.warning(
                "Ping Identity provider initialised with incomplete credentials; "
                "API calls will fail until environment is configured."
            )

        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._http: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    async def _ensure_access_token(self) -> str:
        """Acquire or refresh the PingOne management access token."""
        now = time.time()
        if self._access_token and now < self._token_expires_at - 60:
            return self._access_token

        token_url = f"{PINGONE_AUTH_BASE}/{self.env_id}/as/token"
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
            response = await client.post(
                token_url,
                data={"grant_type": "client_credentials"},
                auth=(self.client_id, self.client_secret),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            payload = response.json()

        self._access_token = payload["access_token"]
        self._token_expires_at = now + payload.get("expires_in", 3600)
        logger.info("ping_token_acquired expires_in=%s", payload.get("expires_in"))
        return self._access_token  # type: ignore[return-value]

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Return an HTTP client with a valid management bearer token."""
        token = await self._ensure_access_token()
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                base_url=f"{PINGONE_API_BASE}/environments/{self.env_id}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                timeout=httpx.Timeout(30.0),
            )
        else:
            self._http.headers["Authorization"] = f"Bearer {token}"
        return self._http

    async def _api_get(self, path: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Authenticated GET against the PingOne Management API."""
        client = await self._get_http_client()
        response = await client.get(path, params=params)
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # User lookup
    # ------------------------------------------------------------------

    async def _find_user(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Find a user by PingOne user ID or email."""
        # Direct ID lookup
        try:
            data = await self._api_get(f"/users/{identifier}")
            return data
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                pass
            else:
                raise

        # Search by email
        try:
            data = await self._api_get(
                "/users",
                params={"filter": f'email eq "{identifier}"'},
            )
            embedded = data.get("_embedded", {})
            users = embedded.get("users", [])
            if users:
                return users[0]
        except Exception:
            logger.exception("ping_user_search_error identifier=%s", identifier)

        return None

    async def get_user_info(self, user_id: str) -> Optional[UserInfo]:
        """Look up a user in PingOne by email or user ID."""
        try:
            data = await self._find_user(user_id)
        except Exception:
            logger.exception("ping_get_user_error identifier=%s", user_id)
            raise

        if data is None:
            logger.info("ping_user_not_found identifier=%s", user_id)
            return None

        ping_id = data.get("id", "")
        groups = await self._get_user_group_names(ping_id)
        roles = await self._get_user_role_names(ping_id)

        name_obj = data.get("name", {})
        display_name = (
            f"{name_obj.get('given', '')} {name_obj.get('family', '')}".strip()
            if isinstance(name_obj, dict)
            else str(name_obj)
        )

        return UserInfo(
            id=ping_id,
            email=data.get("email", ""),
            display_name=display_name,
            department=data.get("department", "") or "",
            groups=groups,
            roles=roles,
            metadata={
                "username": data.get("username", ""),
                "status": data.get("status", ""),
                "population_id": data.get("population", {}).get("id", ""),
                "account_id": data.get("account", {}).get("id", ""),
                "title": data.get("title", ""),
                "created_at": data.get("createdAt", ""),
                "updated_at": data.get("updatedAt", ""),
            },
            provider=self.provider_type.value,
        )

    # ------------------------------------------------------------------
    # Group membership
    # ------------------------------------------------------------------

    async def _get_user_group_names(self, ping_user_id: str) -> List[str]:
        """Return group names for a PingOne user."""
        try:
            data = await self._api_get(f"/users/{ping_user_id}/memberOfGroups")
            embedded = data.get("_embedded", {})
            groups_list = embedded.get("groupMemberships", [])
            return [g.get("name", "") for g in groups_list if g.get("name")]
        except Exception:
            logger.exception("ping_list_groups_error user_id=%s", ping_user_id)
            return []

    async def list_groups(self, user_id: str) -> List[str]:
        """Return group names for a user by email or ID."""
        user = await self.get_user_info(user_id)
        if user is None:
            return []
        return user.groups

    async def check_group_membership(self, user_id: str, group_name: str) -> bool:
        """Check whether the user belongs to *group_name*."""
        groups = await self.list_groups(user_id)
        return group_name in groups

    # ------------------------------------------------------------------
    # Role assignments
    # ------------------------------------------------------------------

    async def _get_user_role_names(self, ping_user_id: str) -> List[str]:
        """Return role assignment names for a PingOne user."""
        try:
            data = await self._api_get(f"/users/{ping_user_id}/roleAssignments")
            embedded = data.get("_embedded", {})
            assignments = embedded.get("roleAssignments", [])
            return [
                a.get("role", {}).get("name", "")
                for a in assignments
                if a.get("role", {}).get("name")
            ]
        except Exception:
            logger.exception("ping_list_roles_error user_id=%s", ping_user_id)
            return []

    # ------------------------------------------------------------------
    # Authentication / token validation
    # ------------------------------------------------------------------

    async def authenticate_user(self, credential: str, **kwargs: Any) -> AuthResult:
        """Validate a bearer token by introspecting via the PingOne token endpoint."""
        try:
            introspect_url = f"{PINGONE_AUTH_BASE}/{self.env_id}/as/introspect"
            async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
                response = await client.post(
                    introspect_url,
                    data={"token": credential},
                    auth=(self.client_id, self.client_secret),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                response.raise_for_status()
                payload = response.json()

            if not payload.get("active", False):
                return AuthResult(success=False, error="Token is inactive or expired")

            sub = payload.get("sub", "")
            user_info = await self.get_user_info(sub) if sub else None

            if user_info is None:
                user_info = UserInfo(
                    id=sub,
                    email=payload.get("email", payload.get("username", "")),
                    display_name=payload.get("name", ""),
                    provider=self.provider_type.value,
                )

            return AuthResult(
                success=True,
                user=user_info,
                token_claims=payload,
                expires_at=str(payload.get("exp", "")),
            )
        except Exception as exc:
            logger.exception("ping_auth_error")
            return AuthResult(success=False, error=str(exc))

    # ------------------------------------------------------------------
    # Context enrichment
    # ------------------------------------------------------------------

    async def enrich_user_context(self, user_info: UserInfo) -> UserInfo:
        """Augment a UserInfo with PingOne-sourced data."""
        full = await self.get_user_info(user_info.email or user_info.id)
        if full is None:
            logger.info("ping_enrich_no_match email=%s id=%s", user_info.email, user_info.id)
            return user_info

        user_info.groups = list(set(user_info.groups + full.groups))
        user_info.roles = list(set(user_info.roles + full.roles))
        user_info.department = full.department or user_info.department
        user_info.display_name = full.display_name or user_info.display_name
        user_info.metadata.update(full.metadata)
        user_info.provider = self.provider_type.value
        return user_info

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def healthcheck(self) -> bool:
        """Verify connectivity to PingOne."""
        try:
            await self._ensure_access_token()
            return True
        except Exception:
            logger.warning("ping_healthcheck_failed")
            return False

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            self._http = None
