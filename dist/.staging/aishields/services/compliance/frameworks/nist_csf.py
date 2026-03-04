"""NIST Cybersecurity Framework (CSF) 2.0."""
from .base import ComplianceFramework, Control
from . import register

@register
class NISTCSFFramework(ComplianceFramework):
    framework_id = "nist-csf"
    framework_name = "NIST Cybersecurity Framework"
    version = "2.0"

    def get_controls(self):
        return [
            Control("GV.OC-01", "Organizational Context", "Organizational mission understood to inform cybersecurity risk decisions", "GOVERN", "high", True, ["org_mission_documented"]),
            Control("GV.RM-01", "Risk Management Strategy", "Risk management objectives established and communicated", "GOVERN", "high", True, ["risk_management_strategy"]),
            Control("GV.SC-01", "Supply Chain Risk", "Cybersecurity supply chain risk management program established", "GOVERN", "medium", True, ["supply_chain_risk_program"]),
            Control("ID.AM-01", "Asset Inventory", "Inventories of hardware managed by the organization", "IDENTIFY", "high", True, ["asset_inventory"]),
            Control("ID.AM-02", "Software Inventory", "Inventories of software and services managed by the organization", "IDENTIFY", "high", True, ["software_inventory"]),
            Control("ID.RA-01", "Vulnerability Identification", "Vulnerabilities in assets identified, validated, and recorded", "IDENTIFY", "high", True, ["vulnerability_scanning"]),
            Control("PR.AA-01", "Identity Management", "Identities and credentials for users and services managed", "PROTECT", "critical", True, ["identity_management", "mfa_enabled"]),
            Control("PR.AA-03", "Access Control", "Access permissions and authorizations managed with least privilege", "PROTECT", "critical", True, ["access_control_policy", "least_privilege"]),
            Control("PR.AT-01", "Security Awareness", "Personnel provided cybersecurity awareness and training", "PROTECT", "medium", True, ["security_training"]),
            Control("PR.DS-01", "Data Protection", "Data-at-rest protected per policy", "PROTECT", "critical", True, ["encryption_at_rest"]),
            Control("PR.DS-02", "Data-in-Transit", "Data-in-transit protected per policy", "PROTECT", "critical", True, ["encryption_in_transit"]),
            Control("PR.PS-01", "Configuration Management", "Configuration management practices established", "PROTECT", "high", True, ["configuration_management"]),
            Control("DE.CM-01", "Network Monitoring", "Networks monitored for potentially adverse events", "DETECT", "high", True, ["network_monitoring"]),
            Control("DE.CM-06", "External Service Monitoring", "External service provider activities monitored", "DETECT", "high", True, ["ai_service_monitoring"]),
            Control("DE.AE-02", "Anomaly Detection", "Potentially adverse events analyzed to characterize anomalies", "DETECT", "high", True, ["anomaly_detection"]),
            Control("RS.MA-01", "Incident Management", "Incident management plan executed in coordination with relevant parties", "RESPOND", "critical", True, ["incident_response_plan"]),
            Control("RS.AN-03", "Incident Analysis", "Analysis performed to determine scope and impact", "RESPOND", "high", True, ["incident_analysis_capability"]),
            Control("RC.RP-01", "Recovery Planning", "Recovery portion of incident response plan executed", "RECOVER", "high", True, ["disaster_recovery_plan"]),
        ]
