"""Abstract base class for pluggable identity providers.

Defines the contract that all identity provider implementations must satisfy,
along with shared data structures for user information and authentication results.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("identity.providers.base")


class ProviderType(str, Enum):
    """Supported identity provider types."""

    ENTRA_ID = "entra_id"
    OKTA = "okta"
    PING = "ping"
    AWS_IAM = "aws_iam"


@dataclass
class UserInfo:
    """Normalized user information returned by any identity provider.

    Attributes:
        id: Provider-specific unique user identifier.
        email: Primary email address.
        display_name: Human-readable display name.
        department: Organisational department (may be empty).
        groups: List of group names the user belongs to.
        roles: List of directory / application roles assigned.
        metadata: Arbitrary provider-specific key-value pairs.
        provider: Which IdP produced this record.
        last_synced: Timestamp when this information was last fetched.
    """

    id: str
    email: str
    display_name: str = ""
    department: str = ""
    groups: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    provider: str = ""
    last_synced: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "display_name": self.display_name,
            "department": self.department,
            "groups": self.groups,
            "roles": self.roles,
            "metadata": self.metadata,
            "provider": self.provider,
            "last_synced": self.last_synced,
        }


@dataclass
class AuthResult:
    """Result of an authentication / token-validation attempt.

    Attributes:
        success: Whether authentication succeeded.
        user: Populated UserInfo when authentication succeeds.
        error: Human-readable error description on failure.
        token_claims: Raw claims extracted from the validated token.
        expires_at: Token expiry time (ISO-8601) if available.
    """

    success: bool
    user: Optional[UserInfo] = None
    error: Optional[str] = None
    token_claims: Dict[str, Any] = field(default_factory=dict)
    expires_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "success": self.success,
            "error": self.error,
            "expires_at": self.expires_at,
        }
        if self.user is not None:
            result["user"] = self.user.to_dict()
        if self.token_claims:
            result["token_claims"] = self.token_claims
        return result


class IdentityProviderBase(ABC):
    """Abstract interface that every identity provider must implement.

    Concrete subclasses wrap vendor-specific SDKs / APIs and translate their
    responses into the normalised :class:`UserInfo` and :class:`AuthResult`
    structures used by the rest of the AIShields platform.
    """

    provider_type: ProviderType

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    @abstractmethod
    async def authenticate_user(
        self, credential: str, **kwargs: Any
    ) -> AuthResult:
        """Validate a bearer token or credential and return an AuthResult.

        Args:
            credential: Bearer token, SAML assertion, or other credential.
            **kwargs: Provider-specific options (e.g. ``audience``).

        Returns:
            AuthResult with ``success=True`` and populated ``user`` on
            success, or ``success=False`` with an ``error`` message.
        """
        ...

    # ------------------------------------------------------------------
    # User lookup
    # ------------------------------------------------------------------

    @abstractmethod
    async def get_user_info(self, user_id: str) -> Optional[UserInfo]:
        """Look up a user by their provider-specific identifier.

        Args:
            user_id: Email, UPN, or opaque ID depending on provider.

        Returns:
            UserInfo if found, ``None`` otherwise.
        """
        ...

    @abstractmethod
    async def enrich_user_context(self, user_info: UserInfo) -> UserInfo:
        """Augment an existing UserInfo with additional IdP data.

        Typically adds group memberships, directory roles, and custom
        attributes that were not present in the initial lookup or token
        claims.

        Args:
            user_info: Partially populated user record.

        Returns:
            The same user record enriched with additional fields.
        """
        ...

    # ------------------------------------------------------------------
    # Group / role queries
    # ------------------------------------------------------------------

    @abstractmethod
    async def list_groups(self, user_id: str) -> List[str]:
        """Return all group names a user belongs to.

        Args:
            user_id: Provider-specific user identifier.

        Returns:
            List of group display names.
        """
        ...

    @abstractmethod
    async def check_group_membership(
        self, user_id: str, group_name: str
    ) -> bool:
        """Check whether *user_id* is a member of *group_name*.

        Args:
            user_id: Provider-specific user identifier.
            group_name: Display name or ID of the group.

        Returns:
            ``True`` if the user is a member.
        """
        ...

    # ------------------------------------------------------------------
    # Lifecycle helpers (optional overrides)
    # ------------------------------------------------------------------

    async def healthcheck(self) -> bool:
        """Return ``True`` if the provider backend is reachable."""
        return True

    async def close(self) -> None:
        """Release any held resources (HTTP sessions, etc.)."""
        pass

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} type={self.provider_type.value}>"
