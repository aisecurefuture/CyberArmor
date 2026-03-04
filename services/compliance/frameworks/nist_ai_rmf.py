"""NIST AI Risk Management Framework (AI RMF) 1.0."""
from .base import ComplianceFramework, Control
from . import register

@register
class NISTAIRMFFramework(ComplianceFramework):
    framework_id = "nist-ai-rmf"
    framework_name = "NIST AI Risk Management Framework"
    version = "1.0"

    def get_controls(self):
        return [
            Control("GOVERN-1.1", "AI Risk Management Policy", "Legal and regulatory requirements involving AI are understood, managed, and documented", "GOVERN", "high", True, ["ai_governance_policy"]),
            Control("GOVERN-1.2", "AI Risk Tolerance", "Trustworthy AI characteristics are integrated into organizational policies", "GOVERN", "high", True, ["ai_risk_tolerance_defined"]),
            Control("GOVERN-2.1", "AI Roles and Responsibilities", "Roles and responsibilities for AI risk management are defined", "GOVERN", "medium", True, ["ai_roles_defined"]),
            Control("GOVERN-4.1", "Organizational AI Culture", "Organizational practices are in place to foster a culture of critical thinking about AI risks", "GOVERN", "medium", True, ["ai_training_program"]),
            Control("GOVERN-6.1", "AI Feedback Mechanisms", "Policies and procedures address AI risks from third-party entities", "GOVERN", "high", True, ["ai_vendor_risk_management"]),
            Control("MAP-1.1", "AI System Context", "Intended purposes, use context, and deployment environment are documented", "MAP", "high", True, ["ai_system_inventory", "ai_use_case_documentation"]),
            Control("MAP-2.1", "AI System Classification", "AI systems are classified based on risk levels", "MAP", "high", True, ["ai_risk_classification"]),
            Control("MAP-3.1", "AI Benefits and Costs", "Benefits and costs of AI systems are assessed", "MAP", "medium", True, ["ai_impact_assessment"]),
            Control("MAP-5.1", "AI Impact Assessment", "Likelihood and magnitude of AI system risks are identified", "MAP", "high", True, ["ai_impact_assessment"]),
            Control("MEASURE-1.1", "AI Metrics", "Appropriate methods and metrics for measuring AI risks are identified", "MEASURE", "high", True, ["ai_monitoring_metrics"]),
            Control("MEASURE-2.1", "AI Evaluation", "AI systems are evaluated for trustworthy characteristics", "MEASURE", "high", True, ["ai_model_evaluation"]),
            Control("MEASURE-2.5", "AI System Testing", "AI system regular testing and monitoring includes assessment of fairness and bias", "MEASURE", "high", True, ["ai_bias_testing", "ai_fairness_evaluation"]),
            Control("MEASURE-2.6", "AI Prompt Injection", "AI systems are tested for adversarial attacks including prompt injection", "MEASURE", "critical", True, ["prompt_injection_detection", "ai_adversarial_testing"]),
            Control("MANAGE-1.1", "AI Risk Prioritization", "AI risks based on assessments and other factors are prioritized, responded to, and managed", "MANAGE", "high", True, ["ai_risk_prioritization"]),
            Control("MANAGE-2.1", "AI Risk Response", "Responses to AI risks are developed, planned, and implemented", "MANAGE", "high", True, ["ai_incident_response_plan"]),
            Control("MANAGE-3.1", "AI Risk Monitoring", "AI risks are monitored on an ongoing basis", "MANAGE", "critical", True, ["ai_service_monitoring", "ai_output_monitoring"]),
            Control("MANAGE-4.1", "AI Decommissioning", "Post-deployment AI system monitoring plans are implemented", "MANAGE", "medium", True, ["ai_lifecycle_management"]),
        ]
