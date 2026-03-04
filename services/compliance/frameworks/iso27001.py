"""ISO 27001:2022 Information Security Management System."""
from .base import ComplianceFramework, Control
from . import register

@register
class ISO27001Framework(ComplianceFramework):
    framework_id = "iso27001"
    framework_name = "ISO 27001"
    version = "2022"

    def get_controls(self):
        return [
            Control("A.5.1", "Policies for Information Security", "Information security policy and topic-specific policies defined, approved, published, communicated", "Organizational", "high", True, ["cybersecurity_policy_documented"]),
            Control("A.5.2", "Information Security Roles", "Information security roles and responsibilities defined and allocated", "Organizational", "medium", True, ["security_roles_defined"]),
            Control("A.5.10", "Acceptable Use", "Rules for acceptable use of information assets identified, documented, implemented", "Organizational", "medium", True, ["acceptable_use_policy"]),
            Control("A.5.23", "Cloud Services Security", "Processes for acquisition, use, management, and exit from cloud services established", "Organizational", "high", True, ["cloud_security_policy"]),
            Control("A.5.29", "Information Security During Disruption", "Plans to maintain security during disruption established", "Organizational", "high", True, ["business_continuity_plan"]),
            Control("A.6.1", "Screening", "Background verification checks on candidates carried out", "People", "medium", True, ["background_checks"]),
            Control("A.6.3", "Information Security Awareness", "Personnel made aware of the information security policy", "People", "medium", True, ["security_training"]),
            Control("A.7.1", "Physical Security Perimeters", "Security perimeters defined and used to protect areas containing information", "Physical", "medium", True, ["physical_security"]),
            Control("A.8.1", "User Endpoint Devices", "Information stored on, processed by, or accessible via endpoint devices protected", "Technological", "high", True, ["endpoint_protection"]),
            Control("A.8.2", "Privileged Access Rights", "Allocation and use of privileged access rights restricted and managed", "Technological", "critical", True, ["privileged_access_management"]),
            Control("A.8.3", "Information Access Restriction", "Access to information restricted in accordance with access control policy", "Technological", "high", True, ["access_control_policy"]),
            Control("A.8.5", "Secure Authentication", "Secure authentication technologies and procedures established", "Technological", "critical", True, ["mfa_enabled", "identity_management"]),
            Control("A.8.9", "Configuration Management", "Configurations including security configurations of hardware, software, services established", "Technological", "high", True, ["configuration_management"]),
            Control("A.8.15", "Logging", "Logs recording activities, exceptions, faults, and other relevant events produced, stored, protected, analysed", "Technological", "high", True, ["audit_logging_enabled"]),
            Control("A.8.16", "Monitoring Activities", "Networks, systems, and applications monitored for anomalous behaviour", "Technological", "high", True, ["network_monitoring", "anomaly_detection"]),
            Control("A.8.24", "Use of Cryptography", "Rules for effective use of cryptography defined and implemented", "Technological", "critical", True, ["encryption_at_rest", "encryption_in_transit"]),
            Control("A.8.25", "Secure Development", "Rules for secure development of software and systems established and applied", "Technological", "high", True, ["secure_sdlc"]),
            Control("A.8.28", "Secure Coding", "Secure coding principles applied to software development", "Technological", "high", True, ["secure_coding_standards"]),
        ]
