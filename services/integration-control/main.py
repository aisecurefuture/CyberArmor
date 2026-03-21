from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from providers.agentic_ai import AgenticAiConnector
from providers.base import IntegrationConnector
from providers.google_workspace import GoogleWorkspaceConnector
from providers.microsoft365 import Microsoft365Connector
from providers.salesforce import SalesforceConnector
from schemas import (
    AgenticAiConfigureRequest,
    ControlActionRequest,
    DiscoveryRequest,
    GoogleWorkspaceConfigureRequest,
    IntegrationConnection,
    IntegrationEvent,
    IntegrationFinding,
    IntegrationPermission,
    IntegrationProvider,
    ProviderConfigureRequest,
    SalesforceConfigureRequest,
)


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("integration_control")

INTEGRATION_CONTROL_API_SECRET = os.getenv("INTEGRATION_CONTROL_API_SECRET", "change-me-integration-control")
ENFORCE_SECURE_SECRETS = os.getenv("CYBERARMOR_ENFORCE_SECURE_SECRETS", "false").strip().lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_DEFAULTS = os.getenv("CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "false").strip().lower() in {"1", "true", "yes", "on"}
SERVICE_STARTED_AT = time.time()
INTEGRATION_POLICY_BLOCK_HIGH_RISK_SCOPE = os.getenv("INTEGRATION_POLICY_BLOCK_HIGH_RISK_SCOPE", "true").strip().lower() in {"1", "true", "yes", "on"}
INTEGRATION_POLICY_BLOCK_UNOWNED = os.getenv("INTEGRATION_POLICY_BLOCK_UNOWNED", "true").strip().lower() in {"1", "true", "yes", "on"}
INTEGRATION_POLICY_BLOCK_STALE_ACTIVE = os.getenv("INTEGRATION_POLICY_BLOCK_STALE_ACTIVE", "false").strip().lower() in {"1", "true", "yes", "on"}
INTEGRATION_POLICY_STALE_DAYS = int(os.getenv("INTEGRATION_POLICY_STALE_DAYS", "30"))


def _enforce_secure_secrets() -> None:
    if not ENFORCE_SECURE_SECRETS or ALLOW_INSECURE_DEFAULTS:
        return
    lowered = (INTEGRATION_CONTROL_API_SECRET or "").strip().lower()
    if not lowered or lowered.startswith("change-me") or "changeme" in lowered:
        raise RuntimeError(
            "Refusing startup with insecure defaults in strict secret mode. "
            "Set strong value for: INTEGRATION_CONTROL_API_SECRET. "
            "For local dev only, set CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true."
        )


_enforce_secure_secrets()

app = FastAPI(title="CyberArmor Integration Control Service", version="0.1.0")

_providers: Dict[str, IntegrationProvider] = {
    "microsoft365": IntegrationProvider(
        provider_id="microsoft365",
        name="Microsoft 365",
        kind="saas_productivity_suite",
        metadata={"supports": ["onedrive", "sharepoint", "entra_oauth_grants", "service_principals"]},
    ),
    "google_workspace": IntegrationProvider(
        provider_id="google_workspace",
        name="Google Workspace",
        kind="saas_productivity_suite",
        metadata={"supports": ["google_drive", "oauth_scopes", "token_inventory"]},
    ),
    "salesforce": IntegrationProvider(
        provider_id="salesforce",
        name="Salesforce",
        kind="saas_crm_platform",
        metadata={"supports": ["connected_apps", "oauth_scopes", "access_policy_findings"]},
    ),
    "agentic_ai": IntegrationProvider(
        provider_id="agentic_ai",
        name="Agentic AI Platforms",
        kind="ai_application_platform",
        metadata={"supports": ["integration_inventory_ingest", "scope_risking", "ownership_and_staleness_findings"]},
    ),
}
_connectors: Dict[str, Dict[str, IntegrationConnector]] = {}
_connections: Dict[str, IntegrationConnection] = {}
_permissions: Dict[str, IntegrationPermission] = {}
_events: Dict[str, IntegrationEvent] = {}
_findings: Dict[str, IntegrationFinding] = {}


class IntegrationPolicyEvaluateRequest(BaseModel):
    tenant_id: str = "default"
    provider: Optional[str] = None
    connection_id: Optional[str] = None


def _verify_api_key(api_key: Optional[str]) -> None:
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if api_key != INTEGRATION_CONTROL_API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


def _get_connector(provider: str, tenant_id: str) -> IntegrationConnector:
    per_provider = _connectors.get(provider, {})
    connector = per_provider.get(tenant_id)
    if connector is None:
        raise HTTPException(
            status_code=404,
            detail=f"Provider '{provider}' is not configured for tenant '{tenant_id}'.",
        )
    return connector


@app.get("/health")
def health():
    return {"status": "ok", "service": "integration-control", "version": "0.1.0"}


@app.get("/ready")
def ready():
    return {"status": "ready", "service": "integration-control", "version": "0.1.0"}


@app.get("/metrics")
def metrics():
    uptime = round(time.time() - SERVICE_STARTED_AT, 3)
    return PlainTextResponse(
        "\n".join(
            [
                "# HELP cyberarmor_integration_control_uptime_seconds Service uptime in seconds",
                "# TYPE cyberarmor_integration_control_uptime_seconds gauge",
                f"cyberarmor_integration_control_uptime_seconds{{service=\"integration-control\",version=\"0.1.0\"}} {uptime}",
            ]
        )
        + "\n",
        media_type="text/plain",
    )


@app.get("/integrations/providers")
def list_providers(x_api_key: Optional[str] = Header(default=None, alias="x-api-key")):
    _verify_api_key(x_api_key)
    return {"providers": [p.model_dump() for p in _providers.values()]}


@app.post("/integrations/providers/microsoft365/configure")
def configure_microsoft365(
    payload: ProviderConfigureRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    connector = Microsoft365Connector(
        tenant_id=payload.tenant_id,
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        authority_tenant_id=payload.authority_tenant_id,
    )
    _connectors.setdefault("microsoft365", {})[payload.tenant_id] = connector
    return {
        "configured": True,
        "provider": "microsoft365",
        "tenant_id": payload.tenant_id,
        "authority_tenant_id": payload.authority_tenant_id or payload.tenant_id,
    }


@app.post("/integrations/providers/google-workspace/configure")
def configure_google_workspace(
    payload: GoogleWorkspaceConfigureRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    connector = GoogleWorkspaceConnector(
        tenant_id=payload.tenant_id,
        access_token=payload.access_token,
        customer_id=payload.customer_id,
        admin_email=payload.admin_email,
    )
    _connectors.setdefault("google_workspace", {})[payload.tenant_id] = connector
    return {
        "configured": True,
        "provider": "google_workspace",
        "tenant_id": payload.tenant_id,
        "customer_id": payload.customer_id,
    }


@app.post("/integrations/providers/salesforce/configure")
def configure_salesforce(
    payload: SalesforceConfigureRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    connector = SalesforceConnector(
        tenant_id=payload.tenant_id,
        instance_url=payload.instance_url,
        access_token=payload.access_token,
    )
    _connectors.setdefault("salesforce", {})[payload.tenant_id] = connector
    return {
        "configured": True,
        "provider": "salesforce",
        "tenant_id": payload.tenant_id,
        "instance_url": payload.instance_url,
    }


@app.post("/integrations/providers/agentic-ai/configure")
def configure_agentic_ai(
    payload: AgenticAiConfigureRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    connector = AgenticAiConnector(
        tenant_id=payload.tenant_id,
        platform=payload.platform,
        source=payload.source,
        inventory=payload.inventory,
    )
    _connectors.setdefault("agentic_ai", {})[payload.tenant_id] = connector
    return {
        "configured": True,
        "provider": "agentic_ai",
        "tenant_id": payload.tenant_id,
        "platform": payload.platform,
        "inventory_items": len(payload.inventory),
    }


@app.post("/integrations/discovery/run")
async def run_discovery(
    payload: DiscoveryRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    provider = payload.provider.strip().lower()
    connector = _get_connector(provider=provider, tenant_id=payload.tenant_id)
    connections, permissions, events, findings = await connector.discover(
        tenant_id=payload.tenant_id, include_events=payload.include_events
    )

    for item in connections:
        _connections[item.connection_id] = item
    for item in permissions:
        _permissions[item.permission_id] = item
    for item in events:
        _events[item.event_id] = item
    for item in findings:
        _findings[item.finding_id] = item

    return {
        "provider": provider,
        "tenant_id": payload.tenant_id,
        "counts": {
            "connections": len(connections),
            "permissions": len(permissions),
            "events": len(events),
            "findings": len(findings),
        },
        "connections": [c.model_dump() for c in connections],
        "permissions": [p.model_dump() for p in permissions],
        "findings": [f.model_dump() for f in findings],
    }


@app.get("/integrations/connections")
def list_connections(
    tenant_id: Optional[str] = None,
    provider: Optional[str] = None,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    out: List[Dict[str, Any]] = []
    for conn in _connections.values():
        if tenant_id and conn.tenant_id != tenant_id:
            continue
        if provider and conn.provider_id != provider:
            continue
        out.append(conn.model_dump())
    return {"connections": out}


@app.get("/integrations/permissions")
def list_permissions(
    tenant_id: Optional[str] = None,
    provider: Optional[str] = None,
    risk_level: Optional[str] = None,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    out: List[Dict[str, Any]] = []
    for perm in _permissions.values():
        if tenant_id and perm.tenant_id != tenant_id:
            continue
        if provider and perm.provider_id != provider:
            continue
        if risk_level and perm.risk_level != risk_level:
            continue
        out.append(perm.model_dump())
    return {"permissions": out}


@app.get("/integrations/findings")
def list_findings(
    tenant_id: Optional[str] = None,
    provider: Optional[str] = None,
    severity: Optional[str] = None,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    out: List[Dict[str, Any]] = []
    for finding in _findings.values():
        if tenant_id and finding.tenant_id != tenant_id:
            continue
        if provider and finding.provider_id != provider:
            continue
        if severity and finding.severity != severity:
            continue
        out.append(finding.model_dump())
    return {"findings": out}


@app.post("/integrations/policy/evaluate")
def evaluate_integration_policy(
    payload: IntegrationPolicyEvaluateRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)

    scoped_connections: List[IntegrationConnection] = []
    for conn in _connections.values():
        if conn.tenant_id != payload.tenant_id:
            continue
        if payload.provider and conn.provider_id != payload.provider:
            continue
        if payload.connection_id and conn.connection_id != payload.connection_id:
            continue
        scoped_connections.append(conn)

    connection_ids = {c.connection_id for c in scoped_connections}
    scoped_permissions: List[IntegrationPermission] = []
    for perm in _permissions.values():
        if perm.tenant_id != payload.tenant_id:
            continue
        if payload.provider and perm.provider_id != payload.provider:
            continue
        if connection_ids and perm.connection_id not in connection_ids:
            continue
        scoped_permissions.append(perm)

    scoped_findings: List[IntegrationFinding] = []
    for finding in _findings.values():
        if finding.tenant_id != payload.tenant_id:
            continue
        if payload.provider and finding.provider_id != payload.provider:
            continue
        if payload.connection_id and finding.connection_id != payload.connection_id:
            continue
        scoped_findings.append(finding)

    violations: List[Dict[str, Any]] = []
    high_risk_scope_count = sum(1 for p in scoped_permissions if p.risk_level == "high")
    unowned_count = sum(1 for f in scoped_findings if f.category == "ownership_gap")
    stale_count = sum(1 for f in scoped_findings if f.category == "stale_integration")

    if INTEGRATION_POLICY_BLOCK_HIGH_RISK_SCOPE and high_risk_scope_count > 0:
        violations.append(
            {
                "rule": "high_risk_scope_block",
                "severity": "high",
                "count": high_risk_scope_count,
                "detail": "High-risk integration scopes detected.",
            }
        )
    if INTEGRATION_POLICY_BLOCK_UNOWNED and unowned_count > 0:
        violations.append(
            {
                "rule": "unowned_integration_block",
                "severity": "high",
                "count": unowned_count,
                "detail": "Unowned integrations detected.",
            }
        )
    if INTEGRATION_POLICY_BLOCK_STALE_ACTIVE and stale_count > 0:
        violations.append(
            {
                "rule": "stale_active_integration_block",
                "severity": "medium",
                "count": stale_count,
                "detail": f"Stale active integrations detected (>{INTEGRATION_POLICY_STALE_DAYS} days).",
            }
        )

    action = "allow"
    reason = "no_policy_violations"
    if any(v["severity"] == "high" for v in violations):
        action = "block"
        reason = "integration_policy_block_violation"
    elif violations:
        action = "warn"
        reason = "integration_policy_warning_violation"

    return {
        "tenant_id": payload.tenant_id,
        "provider": payload.provider,
        "connection_id": payload.connection_id,
        "action": action,
        "reason": reason,
        "violations": violations,
        "summary": {
            "connections": len(scoped_connections),
            "permissions": len(scoped_permissions),
            "findings": len(scoped_findings),
            "high_risk_scopes": high_risk_scope_count,
            "unowned_integrations": unowned_count,
            "stale_integrations": stale_count,
        },
        "policy_config": {
            "block_high_risk_scope": INTEGRATION_POLICY_BLOCK_HIGH_RISK_SCOPE,
            "block_unowned": INTEGRATION_POLICY_BLOCK_UNOWNED,
            "block_stale_active": INTEGRATION_POLICY_BLOCK_STALE_ACTIVE,
            "stale_days": INTEGRATION_POLICY_STALE_DAYS,
        },
    }


@app.post("/integrations/providers/{provider}/consents/{consent_id}/revoke")
async def revoke_consent(
    provider: str,
    consent_id: str,
    payload: ControlActionRequest,
    tenant_id: str,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    connector = _get_connector(provider=provider.strip().lower(), tenant_id=tenant_id)
    result = await connector.revoke_consent(
        tenant_id=tenant_id,
        permission_external_id=consent_id,
        dry_run=payload.dry_run,
    )
    return {
        "ok": True,
        "provider": provider,
        "tenant_id": tenant_id,
        "action": "revoke_consent",
        "reason": payload.reason,
        "result": result,
    }


@app.post("/integrations/providers/{provider}/connections/{connection_id}/disable")
async def disable_connection(
    provider: str,
    connection_id: str,
    payload: ControlActionRequest,
    tenant_id: str,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    connector = _get_connector(provider=provider.strip().lower(), tenant_id=tenant_id)
    result = await connector.disable_connection(
        tenant_id=tenant_id,
        connection_external_id=connection_id,
        dry_run=payload.dry_run,
    )
    return {
        "ok": True,
        "provider": provider,
        "tenant_id": tenant_id,
        "action": "disable_connection",
        "reason": payload.reason,
        "result": result,
    }
