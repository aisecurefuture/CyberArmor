"""NYDFS 23 NYCRR 500 Cybersecurity Regulation."""
from .base import ComplianceFramework, Control
from . import register

@register
class NYDFSFramework(ComplianceFramework):
    framework_id = "nydfs"
    framework_name = "NYDFS 23 NYCRR 500"
    version = "2023 Amendment"

    def get_controls(self):
        return [
            Control("500.2", "Cybersecurity Program", "Maintain a cybersecurity program designed to protect confidentiality, integrity, availability", "Program", "critical", True, ["cybersecurity_program"]),
            Control("500.3", "Cybersecurity Policy", "Implement and maintain a written cybersecurity policy", "Policy", "high", True, ["cybersecurity_policy_documented"]),
            Control("500.4", "CISO", "Designate a qualified individual as CISO", "Governance", "high", True, ["ciso_designated"]),
            Control("500.5", "Penetration Testing", "Conduct annual penetration testing and bi-annual vulnerability assessments", "Assessment", "high", True, ["penetration_testing", "vulnerability_scanning"]),
            Control("500.6", "Audit Trail", "Maintain audit trails to detect and respond to cybersecurity events", "Audit", "high", True, ["audit_logging_enabled", "log_retention_policy"]),
            Control("500.7", "Access Privileges", "Limit access privileges to only those necessary and review periodically", "Access", "high", True, ["least_privilege", "access_reviews"]),
            Control("500.8", "Application Security", "Written procedures and guidelines for secure development practices", "AppSec", "high", True, ["secure_sdlc", "code_review_process"]),
            Control("500.9", "Risk Assessment", "Conduct periodic risk assessments of information systems", "Risk", "high", True, ["risk_assessment_periodic"]),
            Control("500.10", "Cybersecurity Personnel", "Utilize qualified cybersecurity personnel", "Personnel", "medium", True, ["security_team_qualified"]),
            Control("500.11", "Third Party Risk", "Implement written policies and procedures for third-party service providers", "Third Party", "high", True, ["third_party_risk_management"]),
            Control("500.12", "MFA", "Utilize multi-factor authentication for individuals accessing internal networks", "Authentication", "critical", True, ["mfa_enabled"]),
            Control("500.14", "Monitoring", "Implement risk-based policies, procedures, and controls to monitor authorized users", "Monitoring", "high", True, ["user_activity_monitoring", "dlp_configured"]),
            Control("500.15", "Encryption of NPI", "Encrypt nonpublic information in transit and at rest", "Encryption", "critical", True, ["encryption_at_rest", "encryption_in_transit"]),
            Control("500.16", "Incident Response Plan", "Establish a written incident response plan", "Incident Response", "critical", True, ["incident_response_plan"]),
            Control("500.17", "Notification", "Notify the superintendent within 72 hours of a cybersecurity event", "Notification", "high", True, ["breach_notification_process"]),
        ]
