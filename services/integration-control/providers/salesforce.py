from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Tuple

import httpx

from providers.base import IntegrationConnector
from schemas import IntegrationConnection, IntegrationEvent, IntegrationFinding, IntegrationPermission


class SalesforceConnector(IntegrationConnector):
    provider_id = "salesforce"

    def __init__(self, tenant_id: str, instance_url: str, access_token: str):
        self.tenant_id = tenant_id
        self.instance_url = instance_url.rstrip("/")
        self.access_token = access_token
        self.api_version = "v61.0"

    async def _get(self, path: str, params: Dict | None = None) -> Dict:
        url = f"{self.instance_url}/services/data/{self.api_version}{path}"
        async with httpx.AsyncClient(timeout=httpx.Timeout(25.0)) as client:
            resp = await client.get(
                url,
                params=params,
                headers={
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def _post(self, path: str, json_payload: Dict | None = None) -> Dict:
        url = f"{self.instance_url}/services/data/{self.api_version}{path}"
        async with httpx.AsyncClient(timeout=httpx.Timeout(25.0)) as client:
            resp = await client.post(
                url,
                json=json_payload or {},
                headers={
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    def _risk_for_scope(scope: str) -> str:
        s = (scope or "").lower()
        high_terms = ["full", "api", "refresh_token", "offline_access", "manage", "pardot_api"]
        med_terms = ["web", "chatter_api", "id", "openid", "profile", "email"]
        if any(term == s or term in s for term in high_terms):
            return "high"
        if any(term == s or term in s for term in med_terms):
            return "medium"
        return "low"

    async def discover(
        self, tenant_id: str, include_events: bool = False
    ) -> Tuple[List[IntegrationConnection], List[IntegrationPermission], List[IntegrationEvent], List[IntegrationFinding]]:
        connections: List[IntegrationConnection] = []
        permissions: List[IntegrationPermission] = []
        events: List[IntegrationEvent] = []
        findings: List[IntegrationFinding] = []

        # App inventory via ConnectedApplication object.
        app_query = "SELECT Id, Name, ContactEmail, OptionsAllowAdminApprovedUsersOnly FROM ConnectedApplication LIMIT 200"
        apps = await self._get("/query", params={"q": app_query})
        for rec in apps.get("records", []) or []:
            app_id = str(rec.get("Id", ""))
            if not app_id:
                continue
            cid = f"sf_conn_{app_id}"
            connections.append(
                IntegrationConnection(
                    connection_id=cid,
                    provider_id=self.provider_id,
                    tenant_id=tenant_id,
                    external_id=app_id,
                    display_name=str(rec.get("Name") or app_id),
                    connection_type="connected_app",
                    metadata={
                        "contact_email": rec.get("ContactEmail"),
                        "admin_approved_only": rec.get("OptionsAllowAdminApprovedUsersOnly"),
                    },
                )
            )

        # OAuth token / scope visibility from Identity endpoint if available.
        token_scopes: List[str] = []
        try:
            identity = await self._post("/oauth2/userinfo")
            scope_raw = str(identity.get("scope") or "")
            token_scopes = [s for s in scope_raw.split(" ") if s]
        except Exception:
            token_scopes = []

        # If token scopes are available, normalize into permissions.
        target_connection_id = connections[0].connection_id if connections else "sf_conn_unknown"
        for scope in token_scopes:
            risk = self._risk_for_scope(scope)
            pid = f"sf_perm_{hashlib.sha1((target_connection_id + '|' + scope).encode('utf-8')).hexdigest()[:16]}"
            permissions.append(
                IntegrationPermission(
                    permission_id=pid,
                    provider_id=self.provider_id,
                    tenant_id=tenant_id,
                    connection_id=target_connection_id,
                    principal="salesforce-user-or-integration",
                    scope=scope,
                    risk_level=risk,
                    metadata={"source": "oauth_userinfo_scope"},
                )
            )
            if risk == "high":
                findings.append(
                    IntegrationFinding(
                        finding_id=f"sf_find_{pid}",
                        provider_id=self.provider_id,
                        tenant_id=tenant_id,
                        connection_id=target_connection_id,
                        category="overprivileged_scope",
                        severity="high",
                        title="High-risk Salesforce OAuth scope detected",
                        detail=f"Scope '{scope}' observed on integration token.",
                        recommended_action="Review connected app policy, reduce scopes, rotate/revoke token if unnecessary.",
                        metadata={"scope": scope},
                    )
                )

        # Baseline app hardening findings.
        for conn in connections:
            admin_only = bool(conn.metadata.get("admin_approved_only", False))
            if not admin_only:
                findings.append(
                    IntegrationFinding(
                        finding_id=f"sf_find_policy_{conn.external_id}",
                        provider_id=self.provider_id,
                        tenant_id=tenant_id,
                        connection_id=conn.connection_id,
                        category="app_access_policy",
                        severity="medium",
                        title="Connected app not restricted to admin-approved users only",
                        detail=f"Connected app '{conn.display_name}' allows broader user authorization.",
                        recommended_action="Enable admin-approved users policy for sensitive integrations.",
                        metadata={"connected_app_id": conn.external_id},
                    )
                )

        if include_events:
            events.append(
                IntegrationEvent(
                    event_id=f"sf_evt_{int(datetime.now(timezone.utc).timestamp())}",
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
        # In Salesforce this usually maps to token/session revocation.
        if dry_run:
            return {"provider": self.provider_id, "action": "revoke_consent", "dry_run": True, "target": permission_external_id}
        # Revoke endpoint expects token value.
        url = f"{self.instance_url}/services/oauth2/revoke"
        async with httpx.AsyncClient(timeout=httpx.Timeout(25.0)) as client:
            resp = await client.post(
                url,
                params={"token": permission_external_id},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
        return {"provider": self.provider_id, "action": "revoke_consent", "dry_run": False, "target": permission_external_id}

    async def disable_connection(self, tenant_id: str, connection_external_id: str, dry_run: bool = True) -> dict:
        # Direct "disable connected app" API is tenant-policy dependent; provide deterministic control response.
        return {
            "provider": self.provider_id,
            "action": "disable_connection",
            "dry_run": dry_run,
            "target": connection_external_id,
            "status": "manual_action_required",
            "detail": "Disable or block connected app via Salesforce Connected Apps OAuth policies / profiles / permission sets.",
        }

