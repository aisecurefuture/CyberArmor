"""California Consumer Privacy Act / California Privacy Rights Act (CCPA/CPRA)."""
from .base import ComplianceFramework, Control
from . import register

@register
class CCPAFramework(ComplianceFramework):
    framework_id = "ccpa"
    framework_name = "CCPA/CPRA"
    version = "2023"

    def get_controls(self):
        return [
            Control("CCPA-1798.100", "Right to Know", "Consumers have the right to know what personal information is collected, used, shared, or sold", "Consumer Rights", "critical", True, ["privacy_notice_published", "data_inventory"]),
            Control("CCPA-1798.105", "Right to Delete", "Consumers can request deletion of their personal information", "Consumer Rights", "high", True, ["data_deletion_capability"]),
            Control("CCPA-1798.106", "Right to Correct", "Consumers can request correction of inaccurate personal information", "Consumer Rights", "medium", True, ["data_correction_capability"]),
            Control("CCPA-1798.110", "Disclosure Obligations", "Business discloses categories and specific pieces of personal information collected", "Transparency", "high", True, ["data_inventory", "privacy_notice_published"]),
            Control("CCPA-1798.115", "Right to Opt-Out (Sale/Share)", "Consumers can opt-out of sale or sharing of personal information", "Consumer Rights", "critical", True, ["opt_out_mechanism"]),
            Control("CCPA-1798.120", "Do Not Sell or Share", "Consumers' right to opt-out must be honored, including global privacy controls", "Consumer Rights", "high", True, ["opt_out_mechanism", "gpc_support"]),
            Control("CCPA-1798.121", "Right to Limit Sensitive PI", "Consumers can limit use and disclosure of sensitive personal information", "Consumer Rights", "high", True, ["sensitive_data_controls"]),
            Control("CCPA-1798.125", "Non-Discrimination", "Consumers shall not be discriminated against for exercising privacy rights", "Non-Discrimination", "high", True, ["non_discrimination_policy"]),
            Control("CCPA-1798.130", "Consumer Request Methods", "Provide at least two methods for submitting consumer requests, respond within 45 days", "Process", "high", True, ["dsar_process"]),
            Control("CCPA-1798.135", "Do Not Sell Link", "Homepage must include a clear 'Do Not Sell or Share My Personal Information' link", "Transparency", "high", True, ["opt_out_mechanism"]),
            Control("CPRA-1798.140(v)", "Data Minimization", "Processing of personal information is adequate, relevant, and limited to what is necessary", "Principles", "high", True, ["data_minimization"]),
            Control("CPRA-1798.185(a)(15)", "Cybersecurity Audit", "Businesses whose processing presents significant risk must perform annual cybersecurity audits", "Security", "high", True, ["cybersecurity_audit"]),
            Control("CPRA-Risk-Assessment", "Risk Assessment", "Businesses must submit risk assessments for processing that presents significant risk", "Assessment", "high", True, ["privacy_risk_assessment"]),
            Control("CPRA-Automated-Decision", "Automated Decision-Making", "Consumers can opt-out of automated decision-making technology including AI profiling", "AI Rights", "critical", True, ["automated_decision_opt_out", "ai_transparency"]),
        ]
