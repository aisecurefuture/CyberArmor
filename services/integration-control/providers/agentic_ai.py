from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from providers.base import IntegrationConnector
from schemas import IntegrationConnection, IntegrationEvent, IntegrationFinding, IntegrationPermission


class AgenticAiConnector(IntegrationConnector):
    provider_id = "agentic_ai"

    def __init__(self, tenant_id: str, platform: str, source: str, inventory: List[Dict]):
        self.tenant_id = tenant_id
        self.platform = platform
        self.source = source
        self.inventory = inventory or []

    @staticmethod
    def _risk_for_scope(scope: str) -> str:
        s = (scope or "").lower()
        high_terms = [
            "drive.readwrite",
            "sharepoint.full",
            "mail.readwrite",
            "admin",
            "repo:write",
            "workspace.full",
            "secrets.read",
            "files.readwrite.all",
        ]
        med_terms = ["read", "files.read", "calendar.read", "repo:read"]
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

        for idx, item in enumerate(self.inventory):
            app = str(item.get("app") or self.platform)
            external_id = str(item.get("id") or f"{self.platform}-{idx+1}")
            owner = str(item.get("owner") or "").strip()
            status = str(item.get("status") or "active")
            scopes = item.get("scopes") or []
            connectors = item.get("connectors") or []
            last_used_days = int(item.get("last_used_days", 0) or 0)

            cid = f"ai_conn_{hashlib.sha1((app + '|' + external_id).encode('utf-8')).hexdigest()[:16]}"
            connections.append(
                IntegrationConnection(
                    connection_id=cid,
                    provider_id=self.provider_id,
                    tenant_id=tenant_id,
                    external_id=external_id,
                    display_name=app,
                    status=status,
                    connection_type="agentic_app_integration",
                    metadata={
                        "platform": self.platform,
                        "source": self.source,
                        "owner": owner or None,
                        "connectors": connectors,
                        "last_used_days": last_used_days,
                    },
                )
            )

            if not owner:
                findings.append(
                    IntegrationFinding(
                        finding_id=f"ai_find_owner_{cid}",
                        provider_id=self.provider_id,
                        tenant_id=tenant_id,
                        connection_id=cid,
                        category="ownership_gap",
                        severity="high",
                        title="Agentic integration has no recorded owner",
                        detail=f"Integration '{app}' ({external_id}) has no owner metadata.",
                        recommended_action="Assign accountable owner before allowing production use.",
                        metadata={"platform": self.platform},
                    )
                )

            if last_used_days >= 30 and status == "active":
                findings.append(
                    IntegrationFinding(
                        finding_id=f"ai_find_stale_{cid}",
                        provider_id=self.provider_id,
                        tenant_id=tenant_id,
                        connection_id=cid,
                        category="stale_integration",
                        severity="medium",
                        title="Active integration appears stale",
                        detail=f"Integration '{app}' has not been used for {last_used_days} days.",
                        recommended_action="Disable stale integration or require re-approval.",
                        metadata={"last_used_days": last_used_days},
                    )
                )

            for scope in scopes:
                scope_str = str(scope)
                risk = self._risk_for_scope(scope_str)
                pid = f"ai_perm_{hashlib.sha1((cid + '|' + scope_str).encode('utf-8')).hexdigest()[:16]}"
                permissions.append(
                    IntegrationPermission(
                        permission_id=pid,
                        provider_id=self.provider_id,
                        tenant_id=tenant_id,
                        connection_id=cid,
                        principal=owner or "unowned",
                        scope=scope_str,
                        risk_level=risk,
                        metadata={"platform": self.platform, "source": self.source},
                    )
                )
                if risk == "high":
                    findings.append(
                        IntegrationFinding(
                            finding_id=f"ai_find_scope_{pid}",
                            provider_id=self.provider_id,
                            tenant_id=tenant_id,
                            connection_id=cid,
                            category="overprivileged_scope",
                            severity="high",
                            title="High-risk agentic integration scope detected",
                            detail=f"Scope '{scope_str}' detected on integration '{app}'.",
                            recommended_action="Reduce granted scopes and enforce least privilege.",
                            metadata={"scope": scope_str},
                        )
                    )

        if include_events:
            events.append(
                IntegrationEvent(
                    event_id=f"ai_evt_{int(datetime.now(timezone.utc).timestamp())}",
                    provider_id=self.provider_id,
                    tenant_id=tenant_id,
                    event_type="discovery_snapshot_completed",
                    actor="integration-control",
                    payload={
                        "platform": self.platform,
                        "source": self.source,
                        "connections": len(connections),
                        "permissions": len(permissions),
                        "findings": len(findings),
                    },
                )
            )

        return connections, permissions, events, findings

    async def revoke_consent(self, tenant_id: str, permission_external_id: str, dry_run: bool = True) -> dict:
        return {
            "provider": self.provider_id,
            "action": "revoke_consent",
            "dry_run": dry_run,
            "target": permission_external_id,
            "status": "manual_action_required",
            "detail": "Revoke scope/token via source platform admin console (OpenAI/Anthropic/IDE provider).",
        }

    async def disable_connection(self, tenant_id: str, connection_external_id: str, dry_run: bool = True) -> dict:
        return {
            "provider": self.provider_id,
            "action": "disable_connection",
            "dry_run": dry_run,
            "target": connection_external_id,
            "status": "manual_action_required",
            "detail": "Disable integration in source agentic AI platform and remove connector OAuth grants.",
        }

