from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class IntegrationProvider(BaseModel):
    provider_id: str
    name: str
    kind: str
    enabled: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)


class IntegrationConnection(BaseModel):
    connection_id: str
    provider_id: str
    tenant_id: str
    external_id: str
    display_name: str
    status: str = "active"
    connection_type: str = "oauth_app"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)
    last_seen_at: datetime = Field(default_factory=utc_now)


class IntegrationPermission(BaseModel):
    permission_id: str
    provider_id: str
    tenant_id: str
    connection_id: str
    principal: str
    scope: str
    scope_type: str = "oauth_scope"
    risk_level: str = "low"
    granted_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IntegrationEvent(BaseModel):
    event_id: str
    provider_id: str
    tenant_id: str
    connection_id: Optional[str] = None
    event_type: str
    actor: Optional[str] = None
    occurred_at: datetime = Field(default_factory=utc_now)
    payload: Dict[str, Any] = Field(default_factory=dict)


class IntegrationFinding(BaseModel):
    finding_id: str
    provider_id: str
    tenant_id: str
    connection_id: Optional[str] = None
    category: str
    severity: str = "medium"
    title: str
    detail: str
    recommended_action: Optional[str] = None
    confidence: float = 0.8
    created_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DiscoveryRequest(BaseModel):
    provider: str = "microsoft365"
    tenant_id: str = "default"
    include_events: bool = False


class ProviderConfigureRequest(BaseModel):
    tenant_id: str = "default"
    client_id: str
    client_secret: str
    authority_tenant_id: Optional[str] = None


class GoogleWorkspaceConfigureRequest(BaseModel):
    tenant_id: str = "default"
    access_token: str
    customer_id: str = "my_customer"
    admin_email: Optional[str] = None


class SalesforceConfigureRequest(BaseModel):
    tenant_id: str = "default"
    instance_url: str
    access_token: str


class AgenticAiConfigureRequest(BaseModel):
    tenant_id: str = "default"
    platform: str = "openai_codex"
    source: str = "manual_inventory"
    inventory: List[Dict[str, Any]] = Field(default_factory=list)


class ControlActionRequest(BaseModel):
    dry_run: bool = True
    reason: str = "security_control_action"
    metadata: Dict[str, Any] = Field(default_factory=dict)
