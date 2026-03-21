from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Tuple

import httpx

from providers.base import IntegrationConnector
from schemas import IntegrationConnection, IntegrationEvent, IntegrationFinding, IntegrationPermission


class Microsoft365Connector(IntegrationConnector):
    provider_id = "microsoft365"

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, authority_tenant_id: str | None = None):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.authority_tenant_id = authority_tenant_id or tenant_id
        self.graph_base = "https://graph.microsoft.com/v1.0"

    async def _acquire_token(self) -> str:
        token_url = f"https://login.microsoftonline.com/{self.authority_tenant_id}/oauth2/v2.0/token"
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }
        async with httpx.AsyncClient(timeout=httpx.Timeout(25.0)) as client:
            resp = await client.post(token_url, data=payload)
            resp.raise_for_status()
            body = resp.json()
        return str(body.get("access_token", ""))

    async def _graph_get(self, token: str, path: str) -> Dict:
        async with httpx.AsyncClient(timeout=httpx.Timeout(25.0)) as client:
            resp = await client.get(
                f"{self.graph_base}{path}",
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    def _risk_for_scope(scope: str) -> str:
        s = (scope or "").lower()
        high_terms = [
            "mail.readwrite", "files.readwrite.all", "sites.readwrite.all",
            "directory.readwrite.all", "application.readwrite.all", "offline_access",
        ]
        med_terms = ["files.read.all", "sites.read.all", "mail.read", "user.read.all"]
        if any(t in s for t in high_terms):
            return "high"
        if any(t in s for t in med_terms):
            return "medium"
        return "low"

    async def discover(
        self, tenant_id: str, include_events: bool = False
    ) -> Tuple[List[IntegrationConnection], List[IntegrationPermission], List[IntegrationEvent], List[IntegrationFinding]]:
        token = await self._acquire_token()
        if not token:
            raise RuntimeError("Microsoft Graph access token acquisition returned empty token.")

        sps = await self._graph_get(token, "/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled&$top=200")
        grants = await self._graph_get(token, "/oauth2PermissionGrants?$top=200")

        connections: List[IntegrationConnection] = []
        permissions: List[IntegrationPermission] = []
        events: List[IntegrationEvent] = []
        findings: List[IntegrationFinding] = []

        sp_index: Dict[str, Dict] = {}
        for item in sps.get("value", []) or []:
            sp_id = str(item.get("id", ""))
            if not sp_id:
                continue
            sp_index[sp_id] = item
            cid = f"m365_conn_{sp_id}"
            connections.append(
                IntegrationConnection(
                    connection_id=cid,
                    provider_id=self.provider_id,
                    tenant_id=tenant_id,
                    external_id=sp_id,
                    display_name=str(item.get("displayName") or item.get("appId") or sp_id),
                    status="active" if item.get("accountEnabled", True) else "disabled",
                    connection_type="service_principal",
                    metadata={
                        "app_id": item.get("appId"),
                        "service_principal_type": item.get("servicePrincipalType"),
                    },
                )
            )

        for grant in grants.get("value", []) or []:
            grant_id = str(grant.get("id", ""))
            client_id = str(grant.get("clientId", ""))
            scopes = str(grant.get("scope", "")).split()
            connection_id = f"m365_conn_{client_id}"
            principal = str(grant.get("principalId") or grant.get("consentType") or "unknown")
            for scope in scopes:
                perm_id = f"m365_perm_{hashlib.sha1((grant_id + '|' + scope).encode('utf-8')).hexdigest()[:16]}"
                risk = self._risk_for_scope(scope)
                permissions.append(
                    IntegrationPermission(
                        permission_id=perm_id,
                        provider_id=self.provider_id,
                        tenant_id=tenant_id,
                        connection_id=connection_id,
                        principal=principal,
                        scope=scope,
                        risk_level=risk,
                        metadata={
                            "grant_id": grant_id,
                            "client_id": client_id,
                            "consent_type": grant.get("consentType"),
                            "resource_id": grant.get("resourceId"),
                        },
                    )
                )
                if risk == "high":
                    findings.append(
                        IntegrationFinding(
                            finding_id=f"m365_find_{perm_id}",
                            provider_id=self.provider_id,
                            tenant_id=tenant_id,
                            connection_id=connection_id,
                            category="overprivileged_scope",
                            severity="high",
                            title="High-risk Microsoft Graph scope detected",
                            detail=f"Scope '{scope}' granted to connection '{connection_id}'.",
                            recommended_action="Review necessity; revoke consent or disable app if unused.",
                            metadata={"scope": scope, "grant_id": grant_id},
                        )
                    )

        if include_events:
            events.append(
                IntegrationEvent(
                    event_id=f"m365_evt_{int(datetime.now(timezone.utc).timestamp())}",
                    provider_id=self.provider_id,
                    tenant_id=tenant_id,
                    event_type="discovery_snapshot_completed",
                    actor="integration-control",
                    payload={
                        "connections": len(connections),
                        "permissions": len(permissions),
                        "findings": len(findings),
                    },
                )
            )

        return connections, permissions, events, findings

    async def revoke_consent(self, tenant_id: str, permission_external_id: str, dry_run: bool = True) -> dict:
        # permission_external_id should be oauth2PermissionGrant ID.
        if dry_run:
            return {"provider": self.provider_id, "action": "revoke_consent", "dry_run": True, "target": permission_external_id}
        token = await self._acquire_token()
        async with httpx.AsyncClient(timeout=httpx.Timeout(25.0)) as client:
            resp = await client.delete(
                f"{self.graph_base}/oauth2PermissionGrants/{permission_external_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
        return {"provider": self.provider_id, "action": "revoke_consent", "dry_run": False, "target": permission_external_id}

    async def disable_connection(self, tenant_id: str, connection_external_id: str, dry_run: bool = True) -> dict:
        # connection_external_id should be service principal ID.
        if dry_run:
            return {"provider": self.provider_id, "action": "disable_connection", "dry_run": True, "target": connection_external_id}
        token = await self._acquire_token()
        async with httpx.AsyncClient(timeout=httpx.Timeout(25.0)) as client:
            resp = await client.patch(
                f"{self.graph_base}/servicePrincipals/{connection_external_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={"accountEnabled": False},
            )
            resp.raise_for_status()
        return {"provider": self.provider_id, "action": "disable_connection", "dry_run": False, "target": connection_external_id}

