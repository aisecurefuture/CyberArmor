"""CSA Cloud Controls Matrix v4."""
from .base import ComplianceFramework, Control
from . import register

@register
class CSACCMFramework(ComplianceFramework):
    framework_id = "csa-ccm"
    framework_name = "CSA Cloud Controls Matrix"
    version = "v4.0"

    def get_controls(self):
        return [
            Control("AIS-01", "Application Security", "Applications and programming interfaces are designed, developed, deployed, and tested per leading industry standards", "Application Security", "high", True, ["secure_sdlc", "secure_coding_standards"]),
            Control("AIS-04", "Application Security Testing", "Automate application security testing with static, dynamic, and software composition analysis", "Application Security", "high", True, ["sast_configured", "dast_configured"]),
            Control("BCR-01", "Business Continuity Planning", "Determine impact of any disruption of cloud services and establish business continuity plan", "Business Continuity", "high", True, ["business_continuity_plan"]),
            Control("CCC-01", "Change Management Policy", "Define and implement a change management policy", "Change Control", "medium", True, ["change_management_policy"]),
            Control("CEK-01", "Encryption and Key Management", "Establish a data-at-rest and in-transit encryption policy", "Cryptography", "critical", True, ["encryption_at_rest", "encryption_in_transit"]),
            Control("CEK-03", "Data Encryption", "Provide cryptographic protection to data at-rest and in-transit", "Cryptography", "critical", True, ["encryption_at_rest", "encryption_in_transit"]),
            Control("DSP-01", "Data Security Policy", "Establish, document, approve, communicate, apply, evaluate, maintain data security policies", "Data Security", "high", True, ["data_security_policy"]),
            Control("DSP-05", "Data Classification", "Classify data according to its type, sensitivity, and criticality", "Data Security", "high", True, ["data_classification"]),
            Control("GRC-01", "Governance Program", "Establish, document, approve, communicate information security governance program", "Governance", "high", True, ["cybersecurity_program"]),
            Control("HRS-09", "Security Awareness Training", "Establish, document, approve security awareness training programs for all employees", "Human Resources", "medium", True, ["security_training"]),
            Control("IAM-02", "Identity Lifecycle", "Define, implement, and evaluate identity and access management policies", "Identity", "critical", True, ["identity_management"]),
            Control("IAM-04", "Access Management", "Implement and manage access based on need-to-know and least privilege principles", "Identity", "high", True, ["least_privilege", "access_control_policy"]),
            Control("IAM-12", "Multi-Factor Authentication", "Implement multi-factor authentication for all access", "Identity", "critical", True, ["mfa_enabled"]),
            Control("LOG-01", "Logging Policy", "Establish, document, approve logging and monitoring policies", "Logging", "high", True, ["audit_logging_enabled"]),
            Control("LOG-03", "Monitoring and Alerting", "Identify and monitor security-related events within applications and infrastructure", "Logging", "high", True, ["network_monitoring", "siem_configured"]),
            Control("SEF-02", "Incident Management", "Establish, document, and maintain an incident management policy", "Security Incident", "critical", True, ["incident_response_plan"]),
        ]
