export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type IncidentStatus = "open" | "acknowledged" | "investigating" | "resolved" | "closed";
export type PolicyAction = "monitor" | "warn" | "block" | "allow";
export type EndpointOS = "macos" | "windows" | "linux";
export type Classification = "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED";

export interface Incident {
  id: string;
  tenant_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  source: string;
  category: string;
  user?: string;
  endpoint_id?: string;
  model?: string;
  action_taken: PolicyAction;
  details: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  assigned_to?: string;
}

export interface Policy {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  priority: number;
  enabled: boolean;
  action: PolicyAction;
  conditions: ConditionGroup;
  created_at: string;
  updated_at: string;
}

export interface ConditionGroup {
  operator: "AND" | "OR";
  conditions: (Condition | ConditionGroup)[];
}

export interface Condition {
  field: string;
  operator: string;
  value: string | number | boolean | string[];
}

export interface Endpoint {
  id: string;
  tenant_id: string;
  hostname: string;
  os: EndpointOS;
  os_version: string;
  agent_version: string;
  status: "online" | "offline" | "degraded";
  last_seen: string;
  ip_address: string;
  user: string;
  dlp_enabled: boolean;
  pqc_enabled: boolean;
  threats_blocked: number;
  security_score: number;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  description: string;
  control_count: number;
}

export interface ComplianceResult {
  framework_id: string;
  framework_name: string;
  overall_score: number;
  passed: number;
  failed: number;
  partial: number;
  not_assessed: number;
  assessed_at: string;
  findings: ComplianceFinding[];
}

export interface ComplianceFinding {
  control_id: string;
  title: string;
  status: "pass" | "fail" | "partial" | "not_assessed";
  severity: Severity;
  details: string;
}

export interface TelemetryEvent {
  id: string;
  tenant_id: string;
  timestamp: string;
  source: string;
  event_type: string;
  severity: Severity;
  user?: string;
  details: Record<string, unknown>;
}

export interface Alert {
  id: string;
  tenant_id: string;
  incident_id?: string;
  title: string;
  message: string;
  severity: Severity;
  acknowledged: boolean;
  created_at: string;
}

export interface DashboardStats {
  threats_blocked_today: number;
  threats_blocked_week: number;
  active_policies: number;
  total_policies: number;
  compliance_score: number;
  active_endpoints: number;
  total_endpoints: number;
  open_incidents: number;
  critical_incidents: number;
}

export interface ThreatTrend {
  date: string;
  blocked: number;
  warned: number;
  monitored: number;
}

export interface User {
  id: string;
  email: string;
  name: string;
  role: "admin" | "analyst" | "policy_manager" | "viewer";
  tenant_id: string;
}

export interface AuthState {
  authenticated: boolean;
  user: User | null;
  token: string | null;
  biometricEnabled: boolean;
}

export interface AppSettings {
  serverUrl: string;
  apiKey: string;
  tenantId: string;
  biometricEnabled: boolean;
  notificationsEnabled: boolean;
  darkMode: boolean;
  refreshInterval: number;
}
