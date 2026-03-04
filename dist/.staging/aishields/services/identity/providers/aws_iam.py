"""AWS IAM Identity Center (SSO) identity provider.

Uses ``boto3`` to interact with the AWS IAM Identity Center (formerly AWS SSO)
admin APIs for user, group, and permission-set lookups.

Required environment variables:
    AWS_SSO_INSTANCE_ARN - ARN of the IAM Identity Center instance.
    AWS_REGION           - AWS region hosting the instance (e.g. ``us-east-1``).

Standard AWS credential resolution applies (env vars, instance profile, etc.).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

try:
    import boto3  # type: ignore
    from botocore.exceptions import ClientError  # type: ignore
except ImportError:
    boto3 = None  # type: ignore[assignment]
    ClientError = Exception  # type: ignore[misc,assignment]

from .base import AuthResult, IdentityProviderBase, ProviderType, UserInfo

logger = logging.getLogger("identity.providers.aws_iam")


class AWSIAMIdentityCenterProvider(IdentityProviderBase):
    """Identity provider backed by AWS IAM Identity Center."""

    provider_type = ProviderType.AWS_IAM

    def __init__(
        self,
        instance_arn: Optional[str] = None,
        region: Optional[str] = None,
    ) -> None:
        self.instance_arn = instance_arn or os.getenv("AWS_SSO_INSTANCE_ARN", "")
        self.region = region or os.getenv("AWS_REGION", "us-east-1")

        if not self.instance_arn:
            logger.warning(
                "AWS IAM Identity Center provider initialised without "
                "AWS_SSO_INSTANCE_ARN; API calls will fail."
            )

        # Extract the Identity Store ID from the instance ARN lazily.
        self._identity_store_id: Optional[str] = None
        self._identitystore_client: Any = None
        self._sso_admin_client: Any = None

    # ------------------------------------------------------------------
    # Boto3 client helpers
    # ------------------------------------------------------------------

    def _get_identitystore_client(self) -> Any:
        if self._identitystore_client is not None:
            return self._identitystore_client
        if boto3 is None:
            raise RuntimeError(
                "The 'boto3' package is required for the AWS IAM Identity Center "
                "provider. Install it with: pip install boto3"
            )
        self._identitystore_client = boto3.client(
            "identitystore", region_name=self.region
        )
        return self._identitystore_client

    def _get_sso_admin_client(self) -> Any:
        if self._sso_admin_client is not None:
            return self._sso_admin_client
        if boto3 is None:
            raise RuntimeError("boto3 is required for AWS IAM Identity Center provider")
        self._sso_admin_client = boto3.client(
            "sso-admin", region_name=self.region
        )
        return self._sso_admin_client

    async def _get_identity_store_id(self) -> str:
        """Resolve the Identity Store ID from the SSO instance."""
        if self._identity_store_id:
            return self._identity_store_id

        client = self._get_sso_admin_client()
        response = client.list_instances()
        for instance in response.get("Instances", []):
            if instance.get("InstanceArn") == self.instance_arn:
                self._identity_store_id = instance["IdentityStoreId"]
                return self._identity_store_id

        # If instance not found in list, try extracting from env
        store_id = os.getenv("AWS_IDENTITY_STORE_ID", "")
        if store_id:
            self._identity_store_id = store_id
            return store_id

        raise RuntimeError(
            f"Could not resolve Identity Store ID for instance {self.instance_arn}"
        )

    # ------------------------------------------------------------------
    # User lookup
    # ------------------------------------------------------------------

    async def _find_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Find a user in the Identity Store by email address."""
        store_id = await self._get_identity_store_id()
        client = self._get_identitystore_client()

        try:
            response = client.list_users(
                IdentityStoreId=store_id,
                Filters=[{"AttributePath": "UserName", "AttributeValue": email}],
            )
            users = response.get("Users", [])
            if users:
                return users[0]
        except ClientError:
            logger.exception("aws_user_search_error email=%s", email)

        return None

    async def _get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a user directly by their Identity Store user ID."""
        store_id = await self._get_identity_store_id()
        client = self._get_identitystore_client()

        try:
            response = client.describe_user(
                IdentityStoreId=store_id,
                UserId=user_id,
            )
            return response
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "ResourceNotFoundException":
                return None
            raise

    async def get_user_info(self, user_id: str) -> Optional[UserInfo]:
        """Look up a user in AWS IAM Identity Center by email or user ID."""
        try:
            # Try direct ID lookup first
            data = await self._get_user_by_id(user_id)
            if data is None:
                # Fall back to email search
                data = await self._find_user_by_email(user_id)
        except Exception:
            logger.exception("aws_get_user_error identifier=%s", user_id)
            raise

        if data is None:
            logger.info("aws_user_not_found identifier=%s", user_id)
            return None

        aws_user_id = data.get("UserId", "")
        groups = await self._get_user_group_names(aws_user_id)

        name_obj = data.get("Name", {})
        display_name = (
            f"{name_obj.get('GivenName', '')} {name_obj.get('FamilyName', '')}".strip()
        )

        # Extract primary email from Emails list
        emails = data.get("Emails", [])
        primary_email = ""
        for em in emails:
            if em.get("Primary", False):
                primary_email = em.get("Value", "")
                break
        if not primary_email and emails:
            primary_email = emails[0].get("Value", "")

        return UserInfo(
            id=aws_user_id,
            email=primary_email or data.get("UserName", ""),
            display_name=display_name or data.get("DisplayName", ""),
            department="",
            groups=groups,
            roles=[],  # Permission sets resolved separately if needed
            metadata={
                "user_name": data.get("UserName", ""),
                "identity_store_id": data.get("IdentityStoreId", ""),
                "external_ids": [
                    eid.get("Id", "")
                    for eid in data.get("ExternalIds", [])
                ],
                "user_type": data.get("UserType", ""),
                "title": data.get("Title", ""),
                "locale": data.get("Locale", ""),
                "timezone": data.get("Timezone", ""),
            },
            provider=self.provider_type.value,
        )

    # ------------------------------------------------------------------
    # Group membership
    # ------------------------------------------------------------------

    async def _get_user_group_names(self, aws_user_id: str) -> List[str]:
        """Return group display names that the user belongs to."""
        store_id = await self._get_identity_store_id()
        client = self._get_identitystore_client()

        groups: List[str] = []
        try:
            paginator = client.get_paginator("list_group_memberships_for_member")
            pages = paginator.paginate(
                IdentityStoreId=store_id,
                MemberId={"UserId": aws_user_id},
            )
            for page in pages:
                for membership in page.get("GroupMemberships", []):
                    group_id = membership.get("GroupId", "")
                    if group_id:
                        group_name = await self._resolve_group_name(group_id)
                        if group_name:
                            groups.append(group_name)
        except ClientError:
            logger.exception("aws_list_groups_error user_id=%s", aws_user_id)

        return groups

    async def _resolve_group_name(self, group_id: str) -> str:
        """Resolve a group ID to its display name."""
        store_id = await self._get_identity_store_id()
        client = self._get_identitystore_client()
        try:
            response = client.describe_group(
                IdentityStoreId=store_id,
                GroupId=group_id,
            )
            return response.get("DisplayName", "")
        except ClientError:
            logger.warning("aws_resolve_group_error group_id=%s", group_id)
            return ""

    async def list_groups(self, user_id: str) -> List[str]:
        """Return group names for a user by email or Identity Store ID."""
        user = await self.get_user_info(user_id)
        if user is None:
            return []
        return user.groups

    async def check_group_membership(self, user_id: str, group_name: str) -> bool:
        """Check whether the user belongs to *group_name*."""
        groups = await self.list_groups(user_id)
        return group_name in groups

    # ------------------------------------------------------------------
    # Authentication / token validation
    # ------------------------------------------------------------------

    async def authenticate_user(self, credential: str, **kwargs: Any) -> AuthResult:
        """Validate an AWS SSO bearer token.

        AWS IAM Identity Center does not expose a standard token introspection
        endpoint.  This method decodes the JWT locally to extract claims and
        then enriches with Identity Store data.
        """
        try:
            import jwt as pyjwt  # type: ignore

            claims = pyjwt.decode(
                credential,
                options={"verify_signature": False, "verify_aud": False},
            )

            sub = claims.get("sub", "")
            user_info = await self.get_user_info(sub) if sub else None

            if user_info is None:
                user_info = UserInfo(
                    id=sub,
                    email=claims.get("email", ""),
                    display_name=claims.get("name", ""),
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
            logger.exception("aws_auth_error")
            return AuthResult(success=False, error=str(exc))

    # ------------------------------------------------------------------
    # Context enrichment
    # ------------------------------------------------------------------

    async def enrich_user_context(self, user_info: UserInfo) -> UserInfo:
        """Augment a UserInfo with AWS IAM Identity Center data."""
        full = await self.get_user_info(user_info.email or user_info.id)
        if full is None:
            logger.info("aws_enrich_no_match email=%s id=%s", user_info.email, user_info.id)
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
        """Verify connectivity to AWS IAM Identity Center."""
        try:
            client = self._get_sso_admin_client()
            client.list_instances(MaxResults=1)
            return True
        except Exception:
            logger.warning("aws_healthcheck_failed")
            return False

    async def close(self) -> None:
        """Boto3 clients do not require explicit teardown."""
        self._identitystore_client = None
        self._sso_admin_client = None
