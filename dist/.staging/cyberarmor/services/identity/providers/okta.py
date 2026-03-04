"""Okta identity provider.

Uses the Okta REST Management API for user profile, group, and application
assignment lookups.

Required environment variables:
    OKTA_DOMAIN    - Okta org domain (e.g. ``dev-123456.okta.com``).
    OKTA_API_TOKEN - API token with ``okta.users.read``, ``okta.groups.read``
                     scopes at minimum.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx

from .base import AuthResult, IdentityProviderBase, ProviderType, UserInfo

logger = logging.getLogger("identity.providers.okta")


class OktaProvider(IdentityProviderBase):
    """Identity provider backed by Okta."""

    provider_type = ProviderType.OKTA

    def __init__(
        self,
        domain: Optional[str] = None,
        api_token: Optional[str] = None,
    ) -> None:
        self.domain = domain or os.getenv("OKTA_DOMAIN", "")
        self.api_token = api_token or os.getenv("OKTA_API_TOKEN", "")

        if not self.domain or not self.api_token:
            logger.warning(
                "Okta provider initialised with incomplete credentials; "
                "API calls will fail until environment is configured."
            )

        # Normalise domain to include scheme
        if self.domain and not self.domain.startswith("https://"):
            self.domain = f"https://{self.domain}"

        self._http: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Return an HTTP client configured for the Okta API."""
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                base_url=self.domain,
                headers={
                    "Authorization": f"SSWS {self.api_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=httpx.Timeout(30.0),
            )
        return self._http

    async def _api_get(self, path: str, params: Optional[Dict[str, str]] = None) -> Any:
        """Perform an authenticated GET against the Okta Management API."""
        client = await self._get_http_client()
        response = await client.get(path, params=params)
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # User lookup
    # ------------------------------------------------------------------

    async def _find_user(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Find a user by login, email, or Okta ID.

        Tries direct lookup first; falls back to a search query.
        """
        # Attempt direct user lookup (works with Okta user ID or login)
        try:
            return await self._api_get(f"/api/v1/users/{identifier}")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                pass  # Fall through to search
            else:
                raise

        # Search by email / login
        try:
            results = await self._api_get(
                "/api/v1/users",
                params={"search": f'profile.email eq "{identifier}" or profile.login eq "{identifier}"'},
            )
            if results and isinstance(results, list) and len(results) > 0:
                return results[0]
        except Exception:
            logger.exception("okta_user_search_error identifier=%s", identifier)

        return None

    async def get_user_info(self, user_id: str) -> Optional[UserInfo]:
        """Look up a user in Okta by email, login, or Okta ID."""
        try:
            data = await self._find_user(user_id)
        except Exception:
            logger.exception("okta_get_user_error identifier=%s", user_id)
            raise

        if data is None:
            logger.info("okta_user_not_found identifier=%s", user_id)
            return None

        profile = data.get("profile", {})
        okta_id = data.get("id", "")

        groups = await self._get_user_group_names(okta_id)
        app_names = await self._get_user_app_names(okta_id)

        return UserInfo(
            id=okta_id,
            email=profile.get("email", ""),
            display_name=f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip(),
            department=profile.get("department", "") or "",
            groups=groups,
            roles=app_names,
            metadata={
                "login": profile.get("login", ""),
                "title": profile.get("title", ""),
                "manager": profile.get("manager", ""),
                "organization": profile.get("organization", ""),
                "status": data.get("status", ""),
                "last_login": data.get("lastLogin", ""),
            },
            provider=self.provider_type.value,
        )

    # ------------------------------------------------------------------
    # Group membership
    # ------------------------------------------------------------------

    async def _get_user_group_names(self, okta_id: str) -> List[str]:
        """Return display names of all groups the user belongs to."""
        try:
            data = await self._api_get(f"/api/v1/users/{okta_id}/groups")
            return [
                g.get("profile", {}).get("name", "")
                for g in data
                if g.get("profile", {}).get("name")
            ]
        except Exception:
            logger.exception("okta_list_groups_error okta_id=%s", okta_id)
            return []

    async def list_groups(self, user_id: str) -> List[str]:
        """Return group names for a user identified by email/login/ID."""
        user = await self.get_user_info(user_id)
        if user is None:
            return []
        return user.groups

    async def check_group_membership(self, user_id: str, group_name: str) -> bool:
        """Check whether the user belongs to *group_name*."""
        groups = await self.list_groups(user_id)
        return group_name in groups

    # ------------------------------------------------------------------
    # Application assignments
    # ------------------------------------------------------------------

    async def _get_user_app_names(self, okta_id: str) -> List[str]:
        """Return names of applications assigned to the user."""
        try:
            data = await self._api_get(f"/api/v1/users/{okta_id}/appLinks")
            return [
                a.get("label", "")
                for a in data
                if a.get("label")
            ]
        except Exception:
            logger.exception("okta_list_apps_error okta_id=%s", okta_id)
            return []

    # ------------------------------------------------------------------
    # Authentication / token validation
    # ------------------------------------------------------------------

    async def authenticate_user(self, credential: str, **kwargs: Any) -> AuthResult:
        """Validate a bearer token by introspecting it against Okta.

        Falls back to decoding the JWT locally when the introspection
        endpoint is not configured.
        """
        # Attempt token introspection
        try:
            client = await self._get_http_client()
            introspect_url = f"{self.domain}/oauth2/default/v1/introspect"
            response = await client.post(
                introspect_url,
                data={"token": credential, "token_type_hint": "access_token"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            payload = response.json()

            if not payload.get("active", False):
                return AuthResult(success=False, error="Token is inactive or expired")

            uid = payload.get("uid", payload.get("sub", ""))
            user_info = await self.get_user_info(uid) if uid else None

            if user_info is None:
                user_info = UserInfo(
                    id=uid,
                    email=payload.get("sub", ""),
                    display_name=payload.get("username", ""),
                    provider=self.provider_type.value,
                )

            return AuthResult(
                success=True,
                user=user_info,
                token_claims=payload,
                expires_at=str(payload.get("exp", "")),
            )
        except httpx.HTTPStatusError:
            logger.warning("okta_introspect_failed, falling back to local decode")
        except Exception:
            logger.exception("okta_auth_error")

        # Fallback: local JWT decode
        try:
            import jwt as pyjwt  # type: ignore

            claims = pyjwt.decode(
                credential,
                options={"verify_signature": False, "verify_aud": False},
            )
            uid = claims.get("uid", claims.get("sub", ""))
            user_info = await self.get_user_info(uid) if uid else None

            if user_info is None:
                user_info = UserInfo(
                    id=uid,
                    email=claims.get("sub", ""),
                    provider=self.provider_type.value,
                )

            return AuthResult(
                success=True,
                user=user_info,
                token_claims=claims,
                expires_at=str(claims.get("exp", "")),
            )
        except ImportError:
            return AuthResult(success=False, error="PyJWT library not installed")
        except Exception as exc:
            return AuthResult(success=False, error=str(exc))

    # ------------------------------------------------------------------
    # Context enrichment
    # ------------------------------------------------------------------

    async def enrich_user_context(self, user_info: UserInfo) -> UserInfo:
        """Augment a UserInfo with Okta-sourced data."""
        full = await self.get_user_info(user_info.email or user_info.id)
        if full is None:
            logger.info("okta_enrich_no_match email=%s id=%s", user_info.email, user_info.id)
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
        """Verify connectivity to the Okta org."""
        try:
            await self._api_get("/api/v1/org")
            return True
        except Exception:
            logger.warning("okta_healthcheck_failed")
            return False

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            self._http = None
