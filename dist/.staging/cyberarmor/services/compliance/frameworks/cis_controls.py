"""CIS Controls v8."""
from .base import ComplianceFramework, Control
from . import register

@register
class CISControlsFramework(ComplianceFramework):
    framework_id = "cis-controls"
    framework_name = "CIS Controls"
    version = "v8"

    def get_controls(self):
        return [
            Control("CIS-1", "Enterprise Asset Inventory", "Actively manage all enterprise assets connected to infrastructure", "Asset Management", "high", True, ["asset_inventory"]),
            Control("CIS-2", "Software Asset Inventory", "Actively manage all software on the network so only authorized software is installed", "Asset Management", "high", True, ["software_inventory"]),
            Control("CIS-3", "Data Protection", "Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data", "Data Protection", "critical", True, ["data_classification", "dlp_configured"]),
            Control("CIS-4", "Secure Configuration", "Establish and maintain secure configuration of enterprise assets and software", "Configuration", "high", True, ["configuration_baselines", "hardening_standards"]),
            Control("CIS-5", "Account Management", "Use processes and tools to assign and manage authorization to credentials for user accounts", "Identity", "critical", True, ["account_management", "access_reviews"]),
            Control("CIS-6", "Access Control Management", "Use processes and tools to create, assign, manage, and revoke access credentials", "Identity", "critical", True, ["access_control_policy", "rbac_configured"]),
            Control("CIS-7", "Continuous Vulnerability Management", "Develop a plan to continuously assess and track vulnerabilities", "Vulnerability", "high", True, ["vulnerability_scanning", "patch_management"]),
            Control("CIS-8", "Audit Log Management", "Collect, alert, review, and retain audit logs of events", "Logging", "high", True, ["audit_logging_enabled", "log_retention_policy", "siem_configured"]),
            Control("CIS-9", "Email and Web Browser Protections", "Improve protections and detections of threats from email and web vectors", "Network", "high", True, ["email_security", "web_filtering"]),
            Control("CIS-10", "Malware Defenses", "Prevent or control the installation, spread, and execution of malicious applications", "Malware", "high", True, ["antimalware_deployed", "endpoint_protection"]),
            Control("CIS-11", "Data Recovery", "Establish and maintain data recovery practices sufficient to restore in-scope enterprise assets", "Recovery", "high", True, ["backup_policy", "disaster_recovery_plan"]),
            Control("CIS-12", "Network Infrastructure Management", "Establish, implement, and actively manage network devices", "Network", "high", True, ["network_device_management"]),
            Control("CIS-13", "Network Monitoring and Defense", "Operate processes and tooling to establish and maintain comprehensive network monitoring", "Network", "high", True, ["network_monitoring", "intrusion_detection"]),
            Control("CIS-14", "Security Awareness Training", "Establish and maintain a security awareness program to influence behavior among the workforce", "People", "medium", True, ["security_training"]),
            Control("CIS-16", "Application Software Security", "Manage the security life cycle of in-house developed, hosted, or acquired software", "AppSec", "high", True, ["secure_sdlc", "code_review_process"]),
            Control("CIS-17", "Incident Response Management", "Establish a program to develop and maintain an incident response capability", "Incident Response", "critical", True, ["incident_response_plan"]),
        ]
