"""NIST 800-53 Rev 5 Security and Privacy Controls."""
from .base import ComplianceFramework, Control
from . import register

@register
class NIST80053Framework(ComplianceFramework):
    framework_id = "nist-800-53"
    framework_name = "NIST 800-53"
    version = "Rev 5"

    def get_controls(self):
        return [
            Control("AC-2", "Account Management", "Manage system accounts, group memberships, privileges, and access authorizations", "Access Control", "high", True, ["account_management", "access_reviews"]),
            Control("AC-3", "Access Enforcement", "Enforce approved authorizations for logical access", "Access Control", "critical", True, ["access_control_policy", "rbac_configured"]),
            Control("AC-6", "Least Privilege", "Employ principle of least privilege", "Access Control", "high", True, ["least_privilege"]),
            Control("AC-17", "Remote Access", "Establish and manage remote access sessions", "Access Control", "high", True, ["remote_access_policy", "vpn_configured"]),
            Control("AU-2", "Event Logging", "Identify events for logging and frequency of logging", "Audit", "high", True, ["audit_logging_enabled"]),
            Control("AU-6", "Audit Record Review", "Review and analyze audit records for indications of inappropriate activity", "Audit", "high", True, ["audit_review_process", "siem_configured"]),
            Control("AU-12", "Audit Record Generation", "Provide audit record generation capability", "Audit", "high", True, ["audit_logging_enabled"]),
            Control("CA-7", "Continuous Monitoring", "Develop continuous monitoring strategy and implement program", "Assessment", "high", True, ["continuous_monitoring"]),
            Control("CM-2", "Baseline Configuration", "Develop and maintain baseline configurations", "Configuration", "high", True, ["configuration_baselines"]),
            Control("CM-8", "System Component Inventory", "Develop and maintain inventory of system components", "Configuration", "medium", True, ["asset_inventory"]),
            Control("IA-2", "Identification and Authentication", "Uniquely identify and authenticate organizational users", "Identification", "critical", True, ["identity_management", "mfa_enabled"]),
            Control("IA-5", "Authenticator Management", "Manage system authenticators", "Identification", "high", True, ["password_policy", "credential_management"]),
            Control("IR-4", "Incident Handling", "Implement incident handling capability", "Incident Response", "critical", True, ["incident_response_plan", "incident_handling_procedures"]),
            Control("IR-6", "Incident Reporting", "Require incident reporting within defined time frame", "Incident Response", "high", True, ["incident_reporting_process"]),
            Control("RA-5", "Vulnerability Monitoring", "Monitor and scan for vulnerabilities", "Risk Assessment", "high", True, ["vulnerability_scanning"]),
            Control("SC-7", "Boundary Protection", "Monitor and control communications at external managed boundaries", "System Communications", "critical", True, ["firewall_configured", "network_segmentation"]),
            Control("SC-8", "Transmission Confidentiality", "Protect confidentiality of transmitted information", "System Communications", "critical", True, ["encryption_in_transit"]),
            Control("SC-28", "Protection of Information at Rest", "Protect confidentiality and integrity of information at rest", "System Communications", "critical", True, ["encryption_at_rest"]),
            Control("SI-2", "Flaw Remediation", "Identify, report, and correct system flaws", "System Integrity", "high", True, ["patch_management"]),
            Control("SI-4", "System Monitoring", "Monitor system to detect attacks and unauthorized connections", "System Integrity", "high", True, ["intrusion_detection", "network_monitoring"]),
        ]
