"""SOC 2 Type II Trust Services Criteria."""
from .base import ComplianceFramework, Control
from . import register

@register
class SOC2Framework(ComplianceFramework):
    framework_id = "soc2"
    framework_name = "SOC 2 Type II"
    version = "2022"

    def get_controls(self):
        return [
            # Security (Common Criteria)
            Control("CC1.1", "COSO Principle 1", "The entity demonstrates a commitment to integrity and ethical values", "Security", "medium", False, []),
            Control("CC2.1", "Internal Communication", "The entity internally communicates information, including objectives and responsibilities", "Security", "medium", True, ["security_policy_communicated"]),
            Control("CC3.1", "Risk Identification", "The entity specifies objectives with sufficient clarity to enable risk identification and assessment", "Security", "high", True, ["risk_assessment_periodic"]),
            Control("CC5.1", "Control Activities", "The entity selects and develops control activities that contribute to risk mitigation", "Security", "high", True, ["security_controls_implemented"]),
            Control("CC6.1", "Logical Access Security", "The entity implements logical access security software, infrastructure, and architectures", "Security", "critical", True, ["access_control_policy", "identity_management"]),
            Control("CC6.2", "User Authentication", "Prior to issuing system credentials and granting system access, users are registered and authorized", "Security", "critical", True, ["identity_management", "mfa_enabled"]),
            Control("CC6.3", "Role-Based Access", "The entity authorizes, modifies, or removes access based on role", "Security", "high", True, ["rbac_configured", "access_reviews"]),
            Control("CC6.6", "Boundary Protection", "The entity implements logical access security measures to protect boundaries", "Security", "critical", True, ["firewall_configured", "network_segmentation"]),
            Control("CC6.7", "Data Transmission Security", "The entity restricts the transmission of data to authorized external parties", "Security", "high", True, ["encryption_in_transit", "dlp_configured"]),
            Control("CC7.1", "Monitoring Infrastructure", "To meet its objectives, the entity uses detection and monitoring procedures", "Security", "high", True, ["network_monitoring", "siem_configured"]),
            Control("CC7.2", "Anomaly Detection", "The entity monitors system components and operation for anomalies", "Security", "high", True, ["anomaly_detection"]),
            Control("CC7.3", "Security Incident Evaluation", "The entity evaluates events to determine whether they constitute security incidents", "Security", "high", True, ["incident_response_plan"]),
            Control("CC8.1", "Change Management", "The entity authorizes, designs, develops or acquires, configures, tests, approves, and implements changes", "Security", "high", True, ["change_management_policy"]),
            # Availability
            Control("A1.1", "Processing Capacity", "The entity maintains, monitors, and evaluates current processing capacity and use", "Availability", "high", True, ["capacity_monitoring"]),
            Control("A1.2", "Recovery Procedures", "The entity authorizes, designs, develops recovery plans and tests recovery of infrastructure", "Availability", "high", True, ["disaster_recovery_plan", "backup_policy"]),
            # Confidentiality
            Control("C1.1", "Confidential Information", "The entity identifies and maintains confidential information to meet objectives", "Confidentiality", "high", True, ["data_classification", "dlp_configured"]),
            Control("C1.2", "Confidential Data Disposal", "The entity disposes of confidential information to meet objectives", "Confidentiality", "medium", True, ["data_retention_policy"]),
            # Privacy
            Control("P1.1", "Privacy Notice", "The entity provides notice about its privacy practices to meet its objectives", "Privacy", "medium", True, ["privacy_notice_published"]),
            Control("P3.1", "Personal Information Collection", "Personal information is collected consistent with the entity's objectives", "Privacy", "high", True, ["consent_management"]),
        ]
