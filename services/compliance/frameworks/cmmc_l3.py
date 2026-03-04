"""CMMC (Cybersecurity Maturity Model Certification) Level 3."""
from .base import ComplianceFramework, Control
from . import register

@register
class CMMCLevel3Framework(ComplianceFramework):
    framework_id = "cmmc-l3"
    framework_name = "CMMC Level 3"
    version = "2.0"

    def get_controls(self):
        return [
            Control("AC.L2-3.1.1", "Authorized Access Control", "Limit system access to authorized users, processes, and devices", "Access Control", "critical", True, ["access_control_policy", "rbac_configured"]),
            Control("AC.L2-3.1.3", "CUI Flow Enforcement", "Control the flow of CUI in accordance with approved authorizations", "Access Control", "high", True, ["data_flow_controls", "dlp_configured"]),
            Control("AC.L2-3.1.5", "Least Privilege", "Employ the principle of least privilege including for security functions", "Access Control", "high", True, ["least_privilege"]),
            Control("AC.L2-3.1.7", "Privileged Functions", "Prevent non-privileged users from executing privileged functions", "Access Control", "high", True, ["privilege_separation"]),
            Control("AU.L2-3.3.1", "System Auditing", "Create and retain system audit logs and records", "Audit", "high", True, ["audit_logging_enabled", "log_retention_policy"]),
            Control("AU.L2-3.3.2", "User Accountability", "Ensure actions of individual system users can be uniquely traced", "Audit", "high", True, ["user_activity_logging"]),
            Control("CM.L2-3.4.1", "System Baselines", "Establish and maintain baseline configurations and inventories", "Configuration", "high", True, ["configuration_baselines", "asset_inventory"]),
            Control("IA.L2-3.5.1", "User Identification", "Identify system users, processes acting on behalf of users", "Identification", "critical", True, ["identity_management"]),
            Control("IA.L2-3.5.3", "Multi-factor Auth", "Use multi-factor authentication for local and network access", "Identification", "critical", True, ["mfa_enabled"]),
            Control("IR.L2-3.6.1", "Incident Handling", "Establish operational incident-handling capability", "Incident Response", "critical", True, ["incident_response_plan"]),
            Control("IR.L2-3.6.2", "Incident Reporting", "Track, document, and report incidents to designated officials", "Incident Response", "high", True, ["incident_reporting_process"]),
            Control("SC.L2-3.13.1", "Boundary Protection", "Monitor, control, and protect communications at system boundaries", "System Protection", "critical", True, ["firewall_configured", "network_segmentation"]),
            Control("SC.L2-3.13.8", "CUI Encryption Transit", "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission", "System Protection", "critical", True, ["encryption_in_transit", "fips_validated_crypto"]),
            Control("SC.L2-3.13.11", "CUI Encryption Rest", "Protect confidentiality of CUI at rest", "System Protection", "critical", True, ["encryption_at_rest"]),
            Control("SI.L2-3.14.1", "Flaw Remediation", "Identify, report, and correct system flaws in a timely manner", "System Integrity", "high", True, ["patch_management"]),
            Control("SI.L2-3.14.6", "Security Alerts", "Monitor organizational systems including inbound and outbound communications", "System Integrity", "high", True, ["network_monitoring", "siem_configured"]),
        ]
