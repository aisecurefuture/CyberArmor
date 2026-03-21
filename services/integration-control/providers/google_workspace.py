from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Tuple

import httpx

from providers.base import IntegrationConnector
from schemas import IntegrationConnection, IntegrationEvent, IntegrationFinding, IntegrationPermission


class GoogleWorkspaceConnector(IntegrationConnector):
    provider_id = "google_workspace"

    def __init__(self, tenant_id: str, access_token: str, customer_id: str = "my_customer", admin_email: str | None = None):
        self.tenant_id = tenant_id
        self.access_token = access_token
        self.customer_id = customer_id
        self.admin_email = admin_email
        self.drive_base = "https://www.googleapis.com/drive/v3"
        self.admin_reports_base = "https://admin.googleapis.com/admin/reports/v1"

    async def _get(self, url: str, params: Dict | None = None) -> Dict:
        async with httpx.AsyncClient(timeout=httpx.Timeout(25.0)) as client:
            resp = await client.get(
                url,
                params=params,
                headers={"Authorization": f"Bearer {self.access_token}"},
            )
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    def _risk_for_scope(scope: str) -> str:
        s = (scope or "").lower()
        high_terms = [
            "drive", "gmail.modify", "admin.directory.user.readonly", "admin.directory.user", "cloud-platform",
        ]
        med_terms = ["userinfo.email", "userinfo.profile", "calendar.readonly"]
        if any(term in s for term in high_terms):
            return "high"
        if any(term in s for term in med_terms):
            return "medium"
        return "low"

    async def discover(
        self, tenant_id: str, include_events: bool = False
    ) -> Tuple[List[IntegrationConnection], List[IntegrationPermission], List[IntegrationEvent], List[IntegrationFinding]]:
        connections: List[IntegrationConnection] = []
        permissions: List[IntegrationPermission] = []
        events: List[IntegrationEvent] = []
        findings: List[IntegrationFinding] = []

        token_info = await self._get("https://oauth2.googleapis.com/tokeninfo", params={"access_token": self.access_token})
        scopes_raw = str(token_info.get("scope", "")).strip()
        scopes = [s for s in scopes_raw.split(" ") if s]
        oauth_client = str(token_info.get("azp") or token_info.get("aud") or "google_oauth_client")

        connection_id = f"gws_conn_{oauth_client}"
        connections.append(
            IntegrationConnection(
                connection_id=connection_id,
                provider_id=self.provider_id,
                tenant_id=tenant_id,
                external_id=oauth_client,
                display_name=f"Google OAuth Client {oauth_client}",
                connection_type="oauth_client",
                metadata={
                    "issued_to": token_info.get("issued_to"),
                    "audience": token_info.get("aud"),
                    "expires_in": token_info.get("expires_in"),
                    "admin_email": self.admin_email,
                },
            )
        )

        for scope in scopes:
            risk = self._risk_for_scope(scope)
            pid = f"gws_perm_{hashlib.sha1((oauth_client + '|' + scope).encode('utf-8')).hexdigest()[:16]}"
            permissions.append(
                IntegrationPermission(
                    permission_id=pid,
                    provider_id=self.provider_id,
                    tenant_id=tenant_id,
                    connection_id=connection_id,
                    principal=self.admin_email or "workspace-admin",
                    scope=scope,
                    risk_level=risk,
                    metadata={"oauth_client": oauth_client},
                )
            )
            if risk == "high":
                findings.append(
                    IntegrationFinding(
                        finding_id=f"gws_find_{pid}",
                        provider_id=self.provider_id,
                        tenant_id=tenant_id,
                        connection_id=connection_id,
                        category="overprivileged_scope",
                        severity="high",
                        title="High-risk Google scope detected",
                        detail=f"Scope '{scope}' granted to OAuth client '{oauth_client}'.",
                        recommended_action="Review necessity and revoke token/client access if not required.",
                        metadata={"scope": scope, "oauth_client": oauth_client},
                    )
                )

        # Google Drive visibility baseline
        try:
            drive_files = await self._get(
                f"{self.drive_base}/files",
                params={
                    "pageSize": 25,
                    "fields": "files(id,name,mimeType,shared,permissions(emailAddress,domain,role,type,allowFileDiscovery))",
                    "supportsAllDrives": "true",
                    "includeItemsFromAllDrives": "true",
                },
            )
            for f in drive_files.get("files", []) or []:
                if not f.get("shared"):
                    continue
                perms = f.get("permissions", []) or []
                external_or_public = False
                for p in perms:
                    p_type = str(p.get("type", ""))
                    if p_type in {"anyone", "domain"}:
                        external_or_public = True
                        break
                if external_or_public:
                    findings.append(
                        IntegrationFinding(
                            finding_id=f"gws_find_drive_{f.get('id')}",
                            provider_id=self.provider_id,
                            tenant_id=tenant_id,
                            connection_id=connection_id,
                            category="drive_exposure",
                            severity="medium",
                            title="Potentially broad Google Drive sharing detected",
                            detail=f"Drive item '{f.get('name')}' appears shared with domain/anyone.",
                            recommended_action="Review sharing permissions and restrict external/domain-wide access.",
                            metadata={"file_id": f.get("id"), "mime_type": f.get("mimeType")},
                        )
                    )
        except Exception:
            # Non-fatal: keep baseline inventory from token scopes even if Drive listing is unavailable.
            pass

        if include_events:
            events.append(
                IntegrationEvent(
                    event_id=f"gws_evt_{int(datetime.now(timezone.utc).timestamp())}",
                    provider_id=self.provider_id,
                    tenant_id=tenant_id,
                    connection_id=connection_id,
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
        # For Google OAuth, this revokes an access token value.
        if dry_run:
            return {"provider": self.provider_id, "action": "revoke_consent", "dry_run": True, "target": permission_external_id}
        async with httpx.AsyncClient(timeout=httpx.Timeout(25.0)) as client:
            resp = await client.post(
                "https://oauth2.googleapis.com/revoke",
                params={"token": permission_external_id},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
        return {"provider": self.provider_id, "action": "revoke_consent", "dry_run": False, "target": permission_external_id}

    async def disable_connection(self, tenant_id: str, connection_external_id: str, dry_run: bool = True) -> dict:
        # Google does not expose a universal "disable oauth client" API for all client types.
        # Return a deterministic response and keep dry-run by default.
        return {
            "provider": self.provider_id,
            "action": "disable_connection",
            "dry_run": dry_run,
            "target": connection_external_id,
            "status": "manual_action_required",
            "detail": "Disable connection via Google Admin Console App Access Control or workspace app settings.",
        }

