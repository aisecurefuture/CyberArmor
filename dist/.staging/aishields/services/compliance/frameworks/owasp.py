"""OWASP Combined (Top 10 Web, API, Mobile, LLM, AI/Agentic AI, ASVS L3)."""
from .base import ComplianceFramework, Control
from . import register

@register
class OWASPFramework(ComplianceFramework):
    framework_id = "owasp"
    framework_name = "OWASP Combined"
    version = "2024"

    def get_controls(self):
        return [
            # OWASP Top 10 Web (2021)
            Control("A01:2021", "Broken Access Control", "Enforce least privilege access, deny by default, rate limit API access", "Web Top 10", "critical", True, ["access_control_policy", "rbac_configured"]),
            Control("A02:2021", "Cryptographic Failures", "Ensure strong encryption for data in transit and at rest", "Web Top 10", "critical", True, ["encryption_at_rest", "encryption_in_transit"]),
            Control("A03:2021", "Injection", "Validate, sanitize, parameterize all user inputs", "Web Top 10", "critical", True, ["input_validation", "parameterized_queries"]),
            Control("A07:2021", "Identification and Auth Failures", "Implement proper authentication and session management", "Web Top 10", "critical", True, ["mfa_enabled", "session_management"]),
            Control("A09:2021", "Security Logging and Monitoring", "Ensure all login, access control, and input validation failures are logged", "Web Top 10", "high", True, ["audit_logging_enabled", "siem_configured"]),
            # OWASP API Security Top 10 (2023)
            Control("API1:2023", "Broken Object Level Auth", "Implement object level authorization checks in every function accessing data source", "API Top 10", "critical", True, ["api_authorization_checks"]),
            Control("API2:2023", "Broken Authentication", "Implement strong authentication mechanisms for all API endpoints", "API Top 10", "critical", True, ["api_authentication", "mfa_enabled"]),
            Control("API4:2023", "Unrestricted Resource Consumption", "Implement rate limiting, payload size limits, and resource quotas", "API Top 10", "high", True, ["api_rate_limiting"]),
            Control("API8:2023", "Security Misconfiguration", "Implement secure defaults, disable unnecessary features, restrict admin access", "API Top 10", "high", True, ["api_security_configuration"]),
            # OWASP LLM Top 10 (2025)
            Control("LLM01:2025", "Prompt Injection", "Implement input validation, sandboxing, and trust boundary enforcement for LLM inputs", "LLM Top 10", "critical", True, ["prompt_injection_detection", "llm_input_validation"]),
            Control("LLM02:2025", "Sensitive Information Disclosure", "Implement data sanitization, DLP controls for LLM outputs", "LLM Top 10", "critical", True, ["llm_output_filtering", "dlp_configured"]),
            Control("LLM03:2025", "Supply Chain Vulnerabilities", "Vet AI model providers, verify model integrity, monitor supply chain", "LLM Top 10", "high", True, ["ai_vendor_risk_management"]),
            Control("LLM05:2025", "Improper Output Handling", "Validate and sanitize all LLM outputs before use in downstream systems", "LLM Top 10", "critical", True, ["llm_output_validation"]),
            Control("LLM06:2025", "Excessive Agency", "Limit LLM tool access, require human approval for sensitive actions", "LLM Top 10", "critical", True, ["llm_tool_restrictions", "human_in_the_loop"]),
            Control("LLM07:2025", "System Prompt Leakage", "Protect system prompts from extraction through adversarial techniques", "LLM Top 10", "high", True, ["system_prompt_protection"]),
            Control("LLM09:2025", "Misinformation", "Implement fact-checking, grounding, and output verification", "LLM Top 10", "high", True, ["ai_output_monitoring"]),
            # OWASP Agentic AI
            Control("AGENT-01", "Agentic AI Trust Boundaries", "Define and enforce trust boundaries for autonomous AI agents", "Agentic AI", "critical", True, ["ai_trust_boundaries"]),
            Control("AGENT-02", "Agentic AI Tool Access", "Restrict and monitor tools available to AI agents", "Agentic AI", "critical", True, ["llm_tool_restrictions", "ai_service_monitoring"]),
            Control("AGENT-03", "Agentic AI Autonomy Limits", "Implement escalation and human oversight for high-risk AI agent actions", "Agentic AI", "critical", True, ["human_in_the_loop", "ai_escalation_policy"]),
        ]
