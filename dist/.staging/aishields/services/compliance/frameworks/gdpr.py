"""EU General Data Protection Regulation (GDPR)."""
from .base import ComplianceFramework, Control
from . import register

@register
class GDPRFramework(ComplianceFramework):
    framework_id = "gdpr"
    framework_name = "EU GDPR"
    version = "2016/679"

    def get_controls(self):
        return [
            Control("Art.5", "Data Processing Principles", "Personal data processed lawfully, fairly, transparently, with purpose limitation and data minimization", "Principles", "critical", True, ["data_processing_policy", "data_minimization"]),
            Control("Art.6", "Lawful Basis for Processing", "Processing has a documented lawful basis (consent, contract, legal obligation, etc.)", "Lawful Basis", "critical", True, ["lawful_basis_documented"]),
            Control("Art.7", "Consent Management", "Consent is freely given, specific, informed, and unambiguous; easily withdrawable", "Consent", "critical", True, ["consent_management"]),
            Control("Art.12-14", "Transparency and Information", "Data subjects informed about processing in clear, plain language at time of collection", "Transparency", "high", True, ["privacy_notice_published"]),
            Control("Art.15", "Right of Access", "Data subjects can obtain confirmation and copy of personal data being processed", "Data Subject Rights", "high", True, ["dsar_process"]),
            Control("Art.17", "Right to Erasure", "Data subjects can request deletion of personal data without undue delay", "Data Subject Rights", "high", True, ["data_deletion_capability"]),
            Control("Art.20", "Data Portability", "Data subjects can receive their data in structured, commonly used, machine-readable format", "Data Subject Rights", "medium", True, ["data_portability_capability"]),
            Control("Art.25", "Data Protection by Design", "Implement appropriate technical and organizational measures to ensure data protection by design and default", "Design", "critical", True, ["privacy_by_design", "data_minimization"]),
            Control("Art.28", "Processor Agreements", "Processing by processor governed by contract with sufficient guarantees", "Third Party", "high", True, ["dpa_with_processors"]),
            Control("Art.30", "Records of Processing", "Maintain records of processing activities under your responsibility", "Accountability", "high", True, ["processing_records_maintained"]),
            Control("Art.32", "Security of Processing", "Implement appropriate technical and organizational security measures (encryption, pseudonymization, resilience)", "Security", "critical", True, ["encryption_at_rest", "encryption_in_transit", "access_control_policy"]),
            Control("Art.33", "Breach Notification (Authority)", "Notify supervisory authority within 72 hours of becoming aware of a personal data breach", "Breach", "critical", True, ["breach_notification_process"]),
            Control("Art.34", "Breach Notification (Subject)", "Communicate personal data breach to data subject when high risk to rights and freedoms", "Breach", "high", True, ["breach_notification_process"]),
            Control("Art.35", "Data Protection Impact Assessment", "Carry out DPIA where processing likely to result in high risk", "Assessment", "high", True, ["dpia_process"]),
            Control("Art.37", "Data Protection Officer", "Designate a DPO where required by processing activities", "Governance", "high", True, ["dpo_designated"]),
            Control("Art.44-49", "International Transfers", "Personal data transfers outside EEA only with appropriate safeguards", "Transfers", "critical", True, ["international_transfer_safeguards"]),
        ]
