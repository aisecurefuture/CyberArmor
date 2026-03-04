"""PCI-DSS v4.0 Payment Card Industry Data Security Standard."""
from .base import ComplianceFramework, Control
from . import register

@register
class PCIDSSFramework(ComplianceFramework):
    framework_id = "pci-dss"
    framework_name = "PCI-DSS"
    version = "v4.0"

    def get_controls(self):
        return [
            Control("PCI-1.1", "Network Security Controls", "Install and maintain network security controls (firewalls, WAFs)", "Network Security", "critical", True, ["firewall_configured", "network_segmentation"]),
            Control("PCI-1.4", "Cardholder Data Segmentation", "Network connections between trusted and untrusted networks are controlled", "Network Security", "critical", True, ["network_segmentation"]),
            Control("PCI-2.2", "Secure Configuration Standards", "Develop configuration standards for all system components", "Secure Configuration", "high", True, ["configuration_baselines", "hardening_standards"]),
            Control("PCI-3.4", "Render PAN Unreadable", "Render PAN unreadable anywhere it is stored using strong cryptography", "Data Protection", "critical", True, ["encryption_at_rest", "data_masking"]),
            Control("PCI-3.5", "Cryptographic Key Protection", "Primary account numbers are secured with strong cryptography key management", "Data Protection", "critical", True, ["key_management"]),
            Control("PCI-4.1", "Encryption in Transit", "Strong cryptography is used to protect cardholder data during transmission over public networks", "Transmission Security", "critical", True, ["encryption_in_transit", "tls_configured"]),
            Control("PCI-5.2", "Anti-Malware Deployed", "An anti-malware solution is deployed on all systems commonly affected by malware", "Malware Protection", "high", True, ["antimalware_deployed"]),
            Control("PCI-6.2", "Secure Software Development", "Bespoke and custom software is developed securely", "Secure Development", "high", True, ["secure_sdlc", "code_review_process"]),
            Control("PCI-6.4", "Web Application Firewall", "Public-facing web applications are protected against attacks", "Application Security", "high", True, ["waf_configured"]),
            Control("PCI-7.1", "Access Limited by Need to Know", "Access to system components and cardholder data is limited to only those with business need", "Access Control", "critical", True, ["least_privilege", "rbac_configured"]),
            Control("PCI-8.3", "Multi-Factor Authentication", "MFA is implemented for all access into the cardholder data environment", "Authentication", "critical", True, ["mfa_enabled"]),
            Control("PCI-8.6", "Application and System Accounts", "Use of application and system accounts managed securely", "Authentication", "high", True, ["service_account_management"]),
            Control("PCI-10.1", "Audit Log Implemented", "Audit logs are enabled and active for all system components", "Logging", "high", True, ["audit_logging_enabled"]),
            Control("PCI-10.4", "Audit Logs Protected", "Audit logs are protected against destruction and unauthorized modification", "Logging", "high", True, ["log_integrity_protection"]),
            Control("PCI-11.3", "Vulnerability Scanning", "External and internal vulnerabilities are regularly identified and addressed", "Vulnerability", "high", True, ["vulnerability_scanning"]),
            Control("PCI-11.4", "Penetration Testing", "Regular penetration tests performed on network and applications", "Testing", "high", True, ["penetration_testing"]),
            Control("PCI-12.10", "Incident Response Plan", "An incident response plan exists and is ready for immediate activation", "Incident Response", "critical", True, ["incident_response_plan"]),
        ]
