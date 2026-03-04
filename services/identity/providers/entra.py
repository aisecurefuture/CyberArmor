"""Microsoft Entra ID (Azure AD) identity provider.

Uses the MSAL (Microsoft Authentication Library) for client-credential flows and
the Microsoft Graph API for user / group / role lookups.

Required environment variables:
    AZURE_TENANT_ID   - Azure AD tenant (directory) ID.
    AZURE_CLIENT_ID   - Application (client) ID of the registered app.
    AZURE_CLIENT_SECRET - Client secret for the registered app.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx

try:
    import msal  # type: ignore
except ImportError:
    msal = None  # type: ignore[assignment]

from .base import AuthResult, IdentityProviderBase, ProviderType, UserInfo

logger = logging.getLogger("identity.providers.entra")

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
AUTHORITY_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}"
GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]


class EntraIDProvider(IdentityProviderBase):
    """Identity provider backed by Microsoft Entra ID (Azure AD)."""

    provider_type = ProviderType.ENTRA_ID

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> None:
        self.tenant_id = tenant_id or os.getenv("AZURE_TENANT_ID", "")
        self.client_id = client_id or os.getenv("AZURE_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("AZURE_CLIENT_SECRET", "")

        if not all([self.tenant_id, self.client_id, self.client_secret]):
            logger.warning(
                "Entra ID provider initialised with incomplete credentials; "
                "API calls will fail until environment is configured."
            )

        self._authority = AUTHORITY_TEMPLATE.format(tenant_id=self.tenant_id)
        self._msal_app: Optional[Any] = None
        self._http: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_msal_app(self) -> Any:
        """Lazily initialise the MSAL confidential client application."""
        if self._msal_app is not None:
            return self._msal_app
        if msal is None:
            raise RuntimeError(
                "The 'msal' package is required for the Entra ID provider. "
                "Install it with: pip install msal"
            )
        self._msal_app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=self._authority,
        )
        return self._msal_app

    async def _get_access_token(self) -> str:
        """Acquire an application-level access token via client credentials."""
        app = self._get_msal_app()
        result = app.acquire_token_for_client(scopes=GRAPH_SCOPES)
        if "access_token" not in result:
            error_desc = result.get("error_description", result.get("error", "unknown"))
            raise RuntimeError(f"Failed to acquire Entra ID token: {error_desc}")
        return result["access_token"]

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Return an HTTP client with a valid Bearer header."""
        token = await self._get_access_token()
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                base_url=GRAPH_BASE_URL,
                headers={"Authorization": f"Bearer {token}"},
                timeout=httpx.Timeout(30.0),
            )
        else:
            self._http.headers["Authorization"] = f"Bearer {token}"
        return self._http

    async def _graph_get(self, path: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Perform an authenticated GET against the Microsoft Graph API."""
        client = await self._get_http_client()
        response = await client.get(path, params=params)
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # User lookup
    # ------------------------------------------------------------------

    async def _get_user_by_upn_or_id(self, identifier: str) -> Dict[str, Any]:
        """Fetch a user record from Graph by UPN, email, or object ID."""
        select_fields = (
            "id,displayName,mail,userPrincipalName,department,"
            "jobTitle,officeLocation,companyName"
        )
        return await self._graph_get(
            f"/users/{identifier}",
            params={"$select": select_fields},
        )

    async def get_user_info(self, user_id: str) -> Optional[UserInfo]:
        """Look up a user in Entra ID by email, UPN, or object ID."""
        try:
            data = await self._get_user_by_upn_or_id(user_id)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                logger.info("entra_user_not_found identifier=%s", user_id)
                return None
            logger.error("entra_graph_error status=%s identifier=%s", exc.response.status_code, user_id)
            raise
        except Exception:
            logger.exception("entra_get_user_error identifier=%s", user_id)
            raise

        groups = await self._get_user_group_names(data["id"])
        roles = await self._get_directory_roles(data["id"])

        return UserInfo(
            id=data["id"],
            email=data.get("mail") or data.get("userPrincipalName", ""),
            display_name=data.get("displayName", ""),
            department=data.get("department", "") or "",
            groups=groups,
            roles=roles,
            metadata={
                "job_title": data.get("jobTitle", ""),
                "office_location": data.get("officeLocation", ""),
                "company_name": data.get("companyName", ""),
                "user_principal_name": data.get("userPrincipalName", ""),
            },
            provider=self.provider_type.value,
        )

    # ------------------------------------------------------------------
    # Group membership
    # ------------------------------------------------------------------

    async def _get_user_group_names(self, object_id: str) -> List[str]:
        """Return display names of all groups the user belongs to."""
        try:
            data = await self._graph_get(
                f"/users/{object_id}/memberOf",
                params={"$select": "displayName,id,@odata.type"},
            )
            groups: List[str] = []
            for entry in data.get("value", []):
                odata_type = entry.get("@odata.type", "")
                if odata_type == "#microsoft.graph.group":
                    name = entry.get("displayName")
                    if name:
                        groups.append(name)
            return groups
        except Exception:
            logger.exception("entra_list_groups_error object_id=%s", object_id)
            return []

    async def list_groups(self, user_id: str) -> List[str]:
        """Return group names for a user identified by email/UPN/ID."""
        user = await self.get_user_info(user_id)
        if user is None:
            return []
        return user.groups

    async def check_group_membership(self, user_id: str, group_name: str) -> bool:
        """Check whether the user belongs to *group_name*."""
        groups = await self.list_groups(user_id)
        return group_name in groups

    # ------------------------------------------------------------------
    # Directory roles
    # ------------------------------------------------------------------

    async def _get_directory_roles(self, object_id: str) -> List[str]:
        """Return directory role display names assigned to the user."""
        try:
            data = await self._graph_get(
                f"/users/{object_id}/memberOf",
                params={"$select": "displayName,@odata.type"},
            )
            roles: List[str] = []
            for entry in data.get("value", []):
                odata_type = entry.get("@odata.type", "")
                if odata_type == "#microsoft.graph.directoryRole":
                    name = entry.get("displayName")
                    if name:
                        roles.append(name)
            return roles
        except Exception:
            logger.exception("entra_list_roles_error object_id=%s", object_id)
            return []

    # ------------------------------------------------------------------
    # Authentication / token validation
    # ------------------------------------------------------------------

    async def authenticate_user(self, credential: str, **kwargs: Any) -> AuthResult:
        """Validate a bearer token issued by Entra ID.

        This performs a lightweight decode of the JWT to extract claims,
        then enriches the result with Graph API user data.
        """
        try:
            import jwt as pyjwt  # type: ignore

            # Decode without full signature verification for claim extraction.
            # In production, configure jwks_uri verification via PyJWT or MSAL.
            claims = pyjwt.decode(
                credential,
                options={"verify_signature": False, "verify_aud": False},
            )

            upn = claims.get("upn") or claims.get("preferred_username") or claims.get("email", "")
            oid = claims.get("oid", "")

            user_info = await self.get_user_info(upn or oid) if (upn or oid) else None

            if user_info is None:
                user_info = UserInfo(
                    id=oid,
                    email=upn,
                    display_name=claims.get("name", ""),
                    provider=self.provider_type.value,
                )

            return AuthResult(
                success=True,
                user=user_info,
                token_claims=claims,
                expires_at=claims.get("exp"),
            )
        except ImportError:
            logger.warning("PyJWT not installed; cannot decode Entra tokens")
            return AuthResult(success=False, error="PyJWT library not installed")
        except Exception as exc:
            logger.exception("entra_auth_error")
            return AuthResult(success=False, error=str(exc))

    # ------------------------------------------------------------------
    # Context enrichment
    # ------------------------------------------------------------------

    async def enrich_user_context(self, user_info: UserInfo) -> UserInfo:
        """Augment a UserInfo with Entra-sourced groups, roles, metadata."""
        full = await self.get_user_info(user_info.email or user_info.id)
        if full is None:
            logger.info("enrich_no_match email=%s id=%s", user_info.email, user_info.id)
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
        """Check connectivity to the Microsoft Graph API."""
        try:
            await self._graph_get("/organization", params={"$select": "id"})
            return True
        except Exception:
            logger.warning("entra_healthcheck_failed")
            return False

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            self._http = None
