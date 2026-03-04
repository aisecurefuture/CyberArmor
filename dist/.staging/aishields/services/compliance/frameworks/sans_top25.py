"""SANS/CWE Top 25 Most Dangerous Software Weaknesses."""
from .base import ComplianceFramework, Control
from . import register

@register
class SANSTop25Framework(ComplianceFramework):
    framework_id = "sans-top25"
    framework_name = "SANS/CWE Top 25"
    version = "2024"

    def get_controls(self):
        return [
            Control("CWE-787", "Out-of-bounds Write", "Ensure software does not write data past end of intended buffer", "Memory Safety", "critical", True, ["memory_safe_languages", "sast_configured"]),
            Control("CWE-79", "Cross-site Scripting (XSS)", "Properly validate, sanitize, and encode user-controlled data in output", "Web Security", "critical", True, ["input_validation", "output_encoding"]),
            Control("CWE-89", "SQL Injection", "Use parameterized queries and prepared statements", "Injection", "critical", True, ["parameterized_queries", "input_validation"]),
            Control("CWE-416", "Use After Free", "Ensure memory is not accessed after being freed", "Memory Safety", "critical", True, ["memory_safe_languages", "sast_configured"]),
            Control("CWE-78", "OS Command Injection", "Validate and sanitize all inputs used in OS commands", "Injection", "critical", True, ["input_validation", "command_injection_prevention"]),
            Control("CWE-20", "Improper Input Validation", "Validate all input for type, length, format, and range", "Input Validation", "high", True, ["input_validation"]),
            Control("CWE-125", "Out-of-bounds Read", "Validate array and buffer indices before access", "Memory Safety", "high", True, ["memory_safe_languages", "sast_configured"]),
            Control("CWE-22", "Path Traversal", "Validate and canonicalize file paths, restrict to allowed directories", "File Security", "high", True, ["path_traversal_prevention"]),
            Control("CWE-352", "Cross-Site Request Forgery", "Implement CSRF tokens and validate request origin", "Web Security", "high", True, ["csrf_protection"]),
            Control("CWE-434", "Unrestricted File Upload", "Validate file type, size, content; store in non-executable location", "File Security", "high", True, ["file_upload_validation"]),
            Control("CWE-862", "Missing Authorization", "Implement authorization checks on all sensitive resources", "Authorization", "critical", True, ["api_authorization_checks"]),
            Control("CWE-476", "NULL Pointer Dereference", "Check for null before dereferencing pointers", "Memory Safety", "medium", True, ["sast_configured"]),
            Control("CWE-287", "Improper Authentication", "Implement proper authentication for all access paths", "Authentication", "critical", True, ["mfa_enabled", "identity_management"]),
            Control("CWE-190", "Integer Overflow", "Validate arithmetic operations, use safe integer libraries", "Memory Safety", "high", True, ["sast_configured", "secure_coding_standards"]),
            Control("CWE-502", "Deserialization of Untrusted Data", "Avoid deserializing untrusted data, use allowlists for deserialization", "Data Handling", "critical", True, ["input_validation", "deserialization_controls"]),
        ]
