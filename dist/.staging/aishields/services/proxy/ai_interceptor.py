"""AIShields AI/LLM Traffic Interceptor -- mitmproxy Addon.

Specialised addon that detects and inspects traffic to known AI/LLM services.
Works alongside the TransparentProxyAddon to provide deep AI-specific analysis
including:

- Detection of traffic to known AI service endpoints (OpenAI, Anthropic,
  Google AI, Hugging Face, Cohere, Mistral, local Ollama, etc.)
- Inspection of request bodies for prompt injection patterns
- Inspection of response bodies for sensitive data leakage
- Detection of MCP (Model Context Protocol) traffic
- Detection of AI agent tool calls and function calls
- Flagging of data exfiltration attempts via AI APIs
- Integration with the Detection Service for deep content analysis
- Configurable AI service endpoint registry
- Configurable action modes: monitor, warn, block

Usage:
    mitmdump -s ai_interceptor.py            # standalone
    mitmdump -s transparent_proxy.py -s ai_interceptor.py  # combined
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

import httpx
from mitmproxy import ctx, http

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("aishields.ai_interceptor")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DETECTION_SERVICE_URL = os.getenv("DETECTION_SERVICE_URL", "http://detection:8002")
DETECTION_API_KEY = os.getenv("DETECTION_API_KEY", "change-me-detection")
TELEMETRY_ENDPOINT = os.getenv("TELEMETRY_ENDPOINT", "http://siem-connector:8005/ingest")
TELEMETRY_API_KEY = os.getenv("TELEMETRY_API_KEY", "change-me-telemetry")
TENANT_ID = os.getenv("TENANT_ID", "default")
MAX_BODY_SIZE = int(os.getenv("MAX_BODY_SIZE", str(10 * 1024 * 1024)))

# Action mode: monitor (log only), warn (add headers), block (reject requests)
ACTION_MODE = os.getenv("AI_INTERCEPTOR_ACTION_MODE", "monitor")

# Inspection timeout for external service calls (seconds)
INSPECTION_TIMEOUT = float(os.getenv("AI_INSPECTION_TIMEOUT", "5.0"))

# ---------------------------------------------------------------------------
# AI Service Endpoint Registry
# ---------------------------------------------------------------------------
# Each entry: (host_pattern, path_prefix, service_name)
# Patterns support simple glob-style matching via fnmatch.

DEFAULT_AI_ENDPOINTS: List[Dict[str, Any]] = [
    # --- OpenAI ---
    {"host": "api.openai.com", "paths": ["/v1/"], "name": "openai", "category": "llm"},
    {"host": "chat.openai.com", "paths": ["/"], "name": "openai_chat", "category": "llm"},
    # --- Anthropic ---
    {"host": "api.anthropic.com", "paths": ["/v1/"], "name": "anthropic", "category": "llm"},
    # --- Google AI ---
    {"host": "generativelanguage.googleapis.com", "paths": ["/"], "name": "google_ai", "category": "llm"},
    {"host": "aiplatform.googleapis.com", "paths": ["/"], "name": "google_vertex", "category": "llm"},
    {"host": "us-central1-aiplatform.googleapis.com", "paths": ["/"], "name": "google_vertex_regional", "category": "llm"},
    # --- Azure OpenAI ---
    {"host_regex": r".*\.openai\.azure\.com$", "paths": ["/openai/"], "name": "azure_openai", "category": "llm"},
    # --- Hugging Face ---
    {"host": "api-inference.huggingface.co", "paths": ["/"], "name": "huggingface", "category": "llm"},
    {"host": "huggingface.co", "paths": ["/api/"], "name": "huggingface_hub", "category": "llm"},
    # --- Cohere ---
    {"host": "api.cohere.ai", "paths": ["/v1/", "/v2/"], "name": "cohere", "category": "llm"},
    {"host": "api.cohere.com", "paths": ["/v1/", "/v2/"], "name": "cohere", "category": "llm"},
    # --- Mistral ---
    {"host": "api.mistral.ai", "paths": ["/v1/"], "name": "mistral", "category": "llm"},
    # --- Ollama (local) ---
    {"host": "localhost", "paths": ["/api/"], "name": "ollama_local", "category": "local_llm"},
    {"host": "127.0.0.1", "paths": ["/api/"], "name": "ollama_local", "category": "local_llm"},
    {"host_regex": r"ollama.*", "paths": ["/api/"], "name": "ollama", "category": "local_llm"},
    # --- Replicate ---
    {"host": "api.replicate.com", "paths": ["/v1/"], "name": "replicate", "category": "llm"},
    # --- Together AI ---
    {"host": "api.together.xyz", "paths": ["/v1/"], "name": "together", "category": "llm"},
    # --- Perplexity ---
    {"host": "api.perplexity.ai", "paths": ["/"], "name": "perplexity", "category": "llm"},
    # --- Groq ---
    {"host": "api.groq.com", "paths": ["/openai/v1/"], "name": "groq", "category": "llm"},
    # --- AWS Bedrock ---
    {"host_regex": r"bedrock-runtime\..*\.amazonaws\.com$", "paths": ["/"], "name": "aws_bedrock", "category": "llm"},
    # --- MCP Servers (Model Context Protocol) ---
    {"host_regex": r".*", "paths": ["/mcp/", "/.well-known/mcp"], "name": "mcp_server", "category": "mcp"},
]

# Load additional endpoints from environment (JSON array)
_extra_endpoints_raw = os.getenv("AI_EXTRA_ENDPOINTS", "")
if _extra_endpoints_raw:
    try:
        _extra = json.loads(_extra_endpoints_raw)
        if isinstance(_extra, list):
            DEFAULT_AI_ENDPOINTS.extend(_extra)
            logger.info("loaded %d extra AI endpoints from env", len(_extra))
    except json.JSONDecodeError:
        logger.warning("AI_EXTRA_ENDPOINTS env var is not valid JSON; ignored")


# ---------------------------------------------------------------------------
# Prompt injection patterns
# ---------------------------------------------------------------------------
# These are heuristic patterns to flag suspicious prompt content. The Detection
# Service provides the authoritative deep analysis; these act as a fast pre-filter.

PROMPT_INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+)?prior\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|prior|your)\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a|an|in)\s+", re.IGNORECASE),
    re.compile(r"new\s+system\s+prompt[:\s]", re.IGNORECASE),
    re.compile(r"override\s+system\s+prompt", re.IGNORECASE),
    re.compile(r"\bDAN\s+mode\b", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"reveal\s+(your|the)\s+(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"print\s+(your|the)\s+(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"output\s+(your|the)\s+(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"(?:act|behave|respond)\s+as\s+if\s+you\s+(have\s+)?no\s+(restrictions|rules|guidelines)", re.IGNORECASE),
    re.compile(r"<\|system\|>", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"base64\s*decode", re.IGNORECASE),
    re.compile(r"execute\s+(?:this|the\s+following)\s+(?:code|command|script)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Sensitive data patterns (response leakage detection)
# ---------------------------------------------------------------------------
# Fast heuristic patterns; the Detection Service handles thorough PII scanning.

SENSITIVE_DATA_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b")),
    ("api_key_generic", re.compile(r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[\w\-]{20,}['\"]?", re.IGNORECASE)),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("email_batch", re.compile(r"(?:[\w.+-]+@[\w-]+\.[\w.-]+\s*[,;\n]\s*){3,}")),
    ("internal_ip", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")),
]

# ---------------------------------------------------------------------------
# Tool call / function call patterns
# ---------------------------------------------------------------------------
# Detect AI agent tool calls in request/response JSON payloads.

TOOL_CALL_INDICATORS: List[str] = [
    "tool_calls",
    "function_call",
    "tool_use",
    "tool_results",
    "tool_result",
    "function_name",
    "plugin_call",
    "action_input",
    "tool_code",
]

# MCP (Model Context Protocol) indicators
MCP_INDICATORS: List[str] = [
    "jsonrpc",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
    "sampling/createMessage",
    "mcp-protocol-version",
]


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class AITrafficEvent:
    """Structured event emitted for every AI traffic detection."""
    event_id: str
    timestamp: str
    request_id: str
    ai_service: str
    category: str  # llm, local_llm, mcp, embedding, etc.
    direction: str  # request | response
    method: str
    url: str
    client_ip: str
    action_taken: str  # monitor | warn | block
    findings: List[Dict[str, Any]] = field(default_factory=list)
    prompt_injection_detected: bool = False
    sensitive_data_detected: bool = False
    tool_calls_detected: bool = False
    mcp_traffic_detected: bool = False
    exfiltration_risk: bool = False
    risk_score: float = 0.0
    detection_service_result: Optional[Dict[str, Any]] = None
    tenant_id: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": "ai_traffic_inspection",
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "ai_service": self.ai_service,
            "category": self.category,
            "direction": self.direction,
            "method": self.method,
            "url": self.url,
            "client_ip": self.client_ip,
            "action_taken": self.action_taken,
            "findings": self.findings,
            "prompt_injection_detected": self.prompt_injection_detected,
            "sensitive_data_detected": self.sensitive_data_detected,
            "tool_calls_detected": self.tool_calls_detected,
            "mcp_traffic_detected": self.mcp_traffic_detected,
            "exfiltration_risk": self.exfiltration_risk,
            "risk_score": self.risk_score,
            "tenant_id": self.tenant_id,
        }


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------
_http_client: Optional[httpx.AsyncClient] = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(INSPECTION_TIMEOUT, connect=3.0),
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=10),
        )
    return _http_client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_decode(raw: Optional[bytes]) -> str:
    if not raw:
        return ""
    try:
        return raw[:MAX_BODY_SIZE].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _try_parse_json(text: str) -> Optional[Dict[str, Any]]:
    """Attempt to parse a string as JSON. Returns None on failure."""
    if not text or not text.strip():
        return None
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, ValueError):
        pass
    return None


def _get_request_id(flow: http.HTTPFlow) -> str:
    if not hasattr(flow, "_aishields_request_id"):
        flow._aishields_request_id = str(uuid4())  # type: ignore[attr-defined]
    return flow._aishields_request_id  # type: ignore[attr-defined]


def _redact_content(content: str, max_length: int = 512) -> str:
    """Produce a redacted snippet of content suitable for logging.

    Replaces long tokens (potential secrets) with [REDACTED] and truncates.
    """
    if not content:
        return ""
    # Redact anything that looks like a long token/key
    redacted = re.sub(r'[A-Za-z0-9_\-]{32,}', '[REDACTED]', content)
    if len(redacted) > max_length:
        redacted = redacted[:max_length] + "...[truncated]"
    return redacted


# ---------------------------------------------------------------------------
# AI Service Matching
# ---------------------------------------------------------------------------

class AIServiceRegistry:
    """Registry of known AI service endpoints.

    Matches incoming request host + path against registered endpoints to
    determine whether a flow is AI-related traffic.
    """

    def __init__(self, endpoints: Optional[List[Dict[str, Any]]] = None) -> None:
        self._endpoints = endpoints or DEFAULT_AI_ENDPOINTS
        # Pre-compile host regexes
        self._compiled: List[Tuple[Optional[str], Optional[re.Pattern], List[str], str, str]] = []
        for ep in self._endpoints:
            host_exact = ep.get("host")
            host_regex = None
            if "host_regex" in ep:
                try:
                    host_regex = re.compile(ep["host_regex"], re.IGNORECASE)
                except re.error:
                    logger.warning("invalid host_regex in endpoint: %s", ep.get("name"))
                    continue
            paths = ep.get("paths", ["/"])
            name = ep.get("name", "unknown")
            category = ep.get("category", "llm")
            self._compiled.append((host_exact, host_regex, paths, name, category))

    def match(self, host: str, path: str) -> Optional[Tuple[str, str]]:
        """Check if (host, path) matches a known AI service.

        Returns (service_name, category) or None.
        """
        host_lower = host.lower()
        for host_exact, host_regex, paths, name, category in self._compiled:
            # Match host
            host_matched = False
            if host_exact and host_lower == host_exact.lower():
                host_matched = True
            elif host_regex and host_regex.match(host_lower):
                host_matched = True

            if not host_matched:
                continue

            # Match path prefix
            for prefix in paths:
                if path.startswith(prefix):
                    return (name, category)

        return None

    def add_endpoint(self, endpoint: Dict[str, Any]) -> None:
        """Dynamically add a new AI service endpoint."""
        host_exact = endpoint.get("host")
        host_regex = None
        if "host_regex" in endpoint:
            try:
                host_regex = re.compile(endpoint["host_regex"], re.IGNORECASE)
            except re.error:
                logger.warning("invalid host_regex: %s", endpoint.get("host_regex"))
                return
        paths = endpoint.get("paths", ["/"])
        name = endpoint.get("name", "unknown")
        category = endpoint.get("category", "llm")
        self._compiled.append((host_exact, host_regex, paths, name, category))
        self._endpoints.append(endpoint)
        logger.info("added AI endpoint name=%s", name)


# ---------------------------------------------------------------------------
# Content Inspectors
# ---------------------------------------------------------------------------

class PromptInjectionScanner:
    """Fast heuristic scanner for prompt injection patterns in request bodies."""

    def __init__(self, patterns: Optional[List[re.Pattern]] = None) -> None:
        self._patterns = patterns or PROMPT_INJECTION_PATTERNS

    def scan(self, text: str) -> List[Dict[str, Any]]:
        """Scan text for prompt injection indicators.

        Returns a list of finding dicts with pattern name and matched text.
        """
        if not text:
            return []

        findings: List[Dict[str, Any]] = []
        for pattern in self._patterns:
            match = pattern.search(text)
            if match:
                findings.append({
                    "type": "prompt_injection",
                    "pattern": pattern.pattern[:80],
                    "matched_text": _redact_content(match.group(), 100),
                    "position": match.start(),
                })
        return findings


class SensitiveDataScanner:
    """Fast heuristic scanner for sensitive data patterns in response bodies."""

    def __init__(
        self, patterns: Optional[List[Tuple[str, re.Pattern]]] = None
    ) -> None:
        self._patterns = patterns or SENSITIVE_DATA_PATTERNS

    def scan(self, text: str) -> List[Dict[str, Any]]:
        """Scan text for sensitive data indicators.

        Returns a list of finding dicts with data type and redacted match.
        """
        if not text:
            return []

        findings: List[Dict[str, Any]] = []
        seen_types: Set[str] = set()  # Deduplicate by type
        for data_type, pattern in self._patterns:
            if data_type in seen_types:
                continue
            match = pattern.search(text)
            if match:
                seen_types.add(data_type)
                findings.append({
                    "type": "sensitive_data",
                    "data_type": data_type,
                    "matched_text": "[REDACTED]",
                    "position": match.start(),
                })
        return findings


class ToolCallDetector:
    """Detects AI agent tool calls and function calls in JSON payloads."""

    def __init__(self) -> None:
        self._indicators = TOOL_CALL_INDICATORS
        self._mcp_indicators = MCP_INDICATORS

    def detect_tool_calls(self, body_json: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Inspect a parsed JSON body for tool/function call indicators.

        Returns a list of finding dicts describing detected tool calls.
        """
        if not body_json:
            return []

        findings: List[Dict[str, Any]] = []
        body_str = json.dumps(body_json)

        for indicator in self._indicators:
            if indicator in body_str:
                # Extract tool names if possible
                tool_names = self._extract_tool_names(body_json, indicator)
                findings.append({
                    "type": "tool_call",
                    "indicator": indicator,
                    "tool_names": tool_names,
                })

        return findings

    def detect_mcp_traffic(self, body_json: Optional[Dict[str, Any]], headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Detect MCP (Model Context Protocol) traffic patterns.

        Checks both the JSON body and headers for MCP indicators.
        """
        findings: List[Dict[str, Any]] = []

        # Check headers for MCP version
        for header_name, header_val in headers.items():
            if "mcp" in header_name.lower():
                findings.append({
                    "type": "mcp_traffic",
                    "source": "header",
                    "header": header_name,
                    "value": header_val[:64],
                })

        if not body_json:
            return findings

        body_str = json.dumps(body_json)

        # Check for JSON-RPC pattern (MCP uses JSON-RPC 2.0)
        if body_json.get("jsonrpc") == "2.0":
            method = body_json.get("method", "")
            findings.append({
                "type": "mcp_traffic",
                "source": "jsonrpc",
                "method": method,
                "is_mcp_method": any(ind in method for ind in self._mcp_indicators),
            })

        # Check for MCP method patterns in the body
        for indicator in self._mcp_indicators:
            if indicator in body_str and not any(
                f.get("method") == indicator for f in findings
            ):
                findings.append({
                    "type": "mcp_traffic",
                    "source": "body_content",
                    "indicator": indicator,
                })

        return findings

    def _extract_tool_names(self, body: Dict[str, Any], indicator: str) -> List[str]:
        """Best-effort extraction of tool/function names from the payload."""
        names: List[str] = []
        try:
            # OpenAI-style tool_calls
            if indicator == "tool_calls":
                for call in body.get("tool_calls", []):
                    fn = call.get("function", {})
                    if isinstance(fn, dict) and "name" in fn:
                        names.append(fn["name"])
            # OpenAI-style function_call
            elif indicator == "function_call":
                fc = body.get("function_call", {})
                if isinstance(fc, dict) and "name" in fc:
                    names.append(fc["name"])
            # Anthropic-style tool_use
            elif indicator == "tool_use":
                content = body.get("content", [])
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "tool_use":
                            if "name" in block:
                                names.append(block["name"])
        except (TypeError, AttributeError, KeyError):
            pass
        return names


class ExfiltrationDetector:
    """Detect potential data exfiltration via AI APIs.

    Flags requests that appear to be sending large volumes of structured data
    (code, database content, file content) to AI services.
    """

    # Minimum body size in bytes to consider for exfiltration analysis
    MIN_BODY_SIZE = 5000

    # Patterns indicating structured data being sent to an AI API
    EXFILTRATION_PATTERNS: List[Tuple[str, re.Pattern]] = [
        ("database_dump", re.compile(r"(?:INSERT\s+INTO|CREATE\s+TABLE|SELECT\s+.+\s+FROM)\s+", re.IGNORECASE)),
        ("file_content_batch", re.compile(r"(?:file_content|file_data|document_text)\s*[:\"]", re.IGNORECASE)),
        ("base64_large", re.compile(r"[A-Za-z0-9+/]{500,}={0,2}")),
        ("csv_data", re.compile(r"(?:(?:[^,\n]+,){3,}[^,\n]+\n){5,}")),
        ("json_array_large", re.compile(r'\[\s*\{[^}]{100,}\}\s*(?:,\s*\{[^}]{100,}\}\s*){4,}\]')),
        ("source_code_batch", re.compile(r"(?:def |class |function |import |#include |package )", re.IGNORECASE)),
    ]

    def detect(self, body_text: str, body_json: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyse a request body for exfiltration indicators."""
        findings: List[Dict[str, Any]] = []

        if len(body_text) < self.MIN_BODY_SIZE:
            return findings

        for name, pattern in self.EXFILTRATION_PATTERNS:
            matches = pattern.findall(body_text)
            if matches:
                findings.append({
                    "type": "exfiltration_risk",
                    "indicator": name,
                    "match_count": len(matches),
                    "body_size": len(body_text),
                })

        # Check for unusually large message arrays (many messages being sent at once)
        if body_json:
            messages = body_json.get("messages", [])
            if isinstance(messages, list) and len(messages) > 20:
                total_content_len = sum(
                    len(str(m.get("content", "")))
                    for m in messages
                    if isinstance(m, dict)
                )
                if total_content_len > 10000:
                    findings.append({
                        "type": "exfiltration_risk",
                        "indicator": "large_message_batch",
                        "message_count": len(messages),
                        "total_content_length": total_content_len,
                    })

        return findings


# ---------------------------------------------------------------------------
# Detection Service integration
# ---------------------------------------------------------------------------

async def call_detection_service(
    content: str,
    direction: str,
    content_type: str,
    ai_service: str,
    request_url: str,
    local_findings: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Forward content and local findings to the Detection Service for deep analysis.

    The Detection Service performs ML-based analysis that complements the
    heuristic patterns used locally.
    """
    client = _get_http_client()
    payload = {
        "content": content[:MAX_BODY_SIZE],
        "direction": direction,
        "content_type": content_type,
        "ai_service": ai_service,
        "source_url": request_url,
        "tenant_id": TENANT_ID,
        "local_findings": local_findings,
    }
    try:
        resp = await client.post(
            f"{DETECTION_SERVICE_URL}/scan",
            json=payload,
            headers={
                "x-api-key": DETECTION_API_KEY,
                "Content-Type": "application/json",
            },
        )
        if resp.status_code == 200:
            return resp.json()
        logger.warning(
            "detection_service_error status=%d body=%s",
            resp.status_code,
            resp.text[:256],
        )
    except httpx.TimeoutException:
        logger.error("detection_service_timeout url=%s", request_url)
    except Exception as exc:
        logger.error("detection_service_exception err=%s", exc)
    return None


async def emit_ai_telemetry(event: AITrafficEvent) -> None:
    """Emit an AI traffic event to the telemetry pipeline."""
    client = _get_http_client()
    try:
        await client.post(
            TELEMETRY_ENDPOINT,
            json=event.to_dict(),
            headers={
                "x-api-key": TELEMETRY_API_KEY,
                "Content-Type": "application/json",
            },
        )
    except Exception as exc:
        logger.debug("telemetry_emit_failed err=%s", exc)


# ---------------------------------------------------------------------------
# mitmproxy Addon: AIInterceptorAddon
# ---------------------------------------------------------------------------

class AIInterceptorAddon:
    """mitmproxy addon that detects and inspects AI/LLM service traffic.

    This addon is designed to run alongside TransparentProxyAddon. It focuses
    specifically on identifying AI service traffic and performing AI-specific
    inspection (prompt injection, tool calls, MCP, exfiltration).

    The addon operates in one of three action modes:
    - monitor: Log findings only, never modify traffic
    - warn: Add warning headers but allow traffic through
    - block: Block requests that trigger high-risk findings
    """

    def __init__(
        self,
        action_mode: str = ACTION_MODE,
        endpoints: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self._action_mode = action_mode
        self._registry = AIServiceRegistry(endpoints)
        self._injection_scanner = PromptInjectionScanner()
        self._sensitive_scanner = SensitiveDataScanner()
        self._tool_detector = ToolCallDetector()
        self._exfiltration_detector = ExfiltrationDetector()

        # Counters
        self._ai_requests: int = 0
        self._injections_found: int = 0
        self._sensitive_found: int = 0
        self._tool_calls_found: int = 0
        self._mcp_traffic_found: int = 0
        self._exfiltration_flags: int = 0
        self._blocked: int = 0

        logger.info(
            "AIInterceptorAddon initialised action_mode=%s endpoints=%d",
            self._action_mode,
            len(self._registry._endpoints),
        )

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "ai_requests": self._ai_requests,
            "injections_found": self._injections_found,
            "sensitive_data_found": self._sensitive_found,
            "tool_calls_found": self._tool_calls_found,
            "mcp_traffic_found": self._mcp_traffic_found,
            "exfiltration_flags": self._exfiltration_flags,
            "blocked": self._blocked,
        }

    # ---- mitmproxy hooks --------------------------------------------------

    def request(self, flow: http.HTTPFlow) -> None:
        """Request hook -- identify AI traffic and inspect request body."""
        import asyncio
        asyncio.ensure_future(self._handle_request(flow))

    def response(self, flow: http.HTTPFlow) -> None:
        """Response hook -- inspect AI service responses for sensitive data."""
        import asyncio
        asyncio.ensure_future(self._handle_response(flow))

    # ---- Async handlers ---------------------------------------------------

    async def _handle_request(self, flow: http.HTTPFlow) -> None:
        """Inspect an outbound request for AI service traffic."""
        host = flow.request.host
        path = flow.request.path
        match = self._registry.match(host, path)

        if match is None:
            # Not AI traffic -- skip
            return

        service_name, category = match
        self._ai_requests += 1
        request_id = _get_request_id(flow)
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"

        logger.info(
            "ai_traffic_detected request_id=%s service=%s category=%s url=%s",
            request_id,
            service_name,
            category,
            flow.request.pretty_url,
        )

        # Tag the flow so the response hook knows this is AI traffic
        flow._aishields_ai_service = service_name  # type: ignore[attr-defined]
        flow._aishields_ai_category = category  # type: ignore[attr-defined]

        body_text = _safe_decode(flow.request.get_content())
        body_json = _try_parse_json(body_text)
        headers_dict = dict(flow.request.headers)
        all_findings: List[Dict[str, Any]] = []

        # --- Prompt injection scan ---
        injection_findings = self._injection_scanner.scan(body_text)
        if injection_findings:
            self._injections_found += len(injection_findings)
            all_findings.extend(injection_findings)

        # --- Tool call detection ---
        tool_findings = self._tool_detector.detect_tool_calls(body_json)
        if tool_findings:
            self._tool_calls_found += len(tool_findings)
            all_findings.extend(tool_findings)

        # --- MCP traffic detection ---
        mcp_findings = self._tool_detector.detect_mcp_traffic(body_json, headers_dict)
        if mcp_findings:
            self._mcp_traffic_found += len(mcp_findings)
            all_findings.extend(mcp_findings)

        # --- Exfiltration detection ---
        exfil_findings = self._exfiltration_detector.detect(body_text, body_json)
        if exfil_findings:
            self._exfiltration_flags += len(exfil_findings)
            all_findings.extend(exfil_findings)

        # --- Deep analysis via Detection Service ---
        detection_result = None
        if all_findings or len(body_text) > 1000:
            detection_result = await call_detection_service(
                content=body_text,
                direction="request",
                content_type=headers_dict.get("content-type", ""),
                ai_service=service_name,
                request_url=flow.request.pretty_url,
                local_findings=all_findings,
            )

        # --- Determine action ---
        action_taken = self._determine_action(all_findings, detection_result)

        # --- Build and emit telemetry event ---
        event = AITrafficEvent(
            event_id=str(uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_id=request_id,
            ai_service=service_name,
            category=category,
            direction="request",
            method=flow.request.method,
            url=flow.request.pretty_url,
            client_ip=client_ip,
            action_taken=action_taken,
            findings=all_findings,
            prompt_injection_detected=len(injection_findings) > 0,
            sensitive_data_detected=False,
            tool_calls_detected=len(tool_findings) > 0,
            mcp_traffic_detected=len(mcp_findings) > 0,
            exfiltration_risk=len(exfil_findings) > 0,
            risk_score=self._compute_risk_score(all_findings, detection_result),
            detection_service_result=detection_result,
            tenant_id=TENANT_ID,
        )
        await emit_ai_telemetry(event)

        # --- Enforce action ---
        if action_taken == "block":
            self._blocked += 1
            reason = self._build_block_reason(all_findings)
            flow.response = http.Response.make(
                403,
                json.dumps({
                    "error": "ai_request_blocked",
                    "reason": reason,
                    "request_id": request_id,
                    "service": "aishields-ai-interceptor",
                    "findings_count": len(all_findings),
                }).encode("utf-8"),
                {
                    "Content-Type": "application/json",
                    "X-AIShields-Request-ID": request_id,
                    "X-AIShields-Action": "block",
                },
            )
            logger.warning(
                "ai_request_blocked request_id=%s service=%s reason=%s findings=%d",
                request_id,
                service_name,
                reason,
                len(all_findings),
            )
        elif action_taken == "warn":
            flow.request.headers["X-AIShields-AI-Warning"] = self._build_block_reason(all_findings)
            flow.request.headers["X-AIShields-AI-Service"] = service_name
            flow.request.headers["X-AIShields-Request-ID"] = request_id

    async def _handle_response(self, flow: http.HTTPFlow) -> None:
        """Inspect an AI service response for sensitive data leakage."""
        service_name = getattr(flow, "_aishields_ai_service", None)
        if not service_name:
            # Not flagged as AI traffic in the request phase
            return

        if flow.response is None:
            return

        request_id = _get_request_id(flow)
        category = getattr(flow, "_aishields_ai_category", "llm")
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"

        body_text = _safe_decode(flow.response.get_content())
        if not body_text:
            return

        body_json = _try_parse_json(body_text)
        headers_dict = dict(flow.response.headers)
        all_findings: List[Dict[str, Any]] = []

        # --- Sensitive data scan on response ---
        sensitive_findings = self._sensitive_scanner.scan(body_text)
        if sensitive_findings:
            self._sensitive_found += len(sensitive_findings)
            all_findings.extend(sensitive_findings)

        # --- Tool call results in response ---
        tool_findings = self._tool_detector.detect_tool_calls(body_json)
        if tool_findings:
            self._tool_calls_found += len(tool_findings)
            all_findings.extend(tool_findings)

        # --- MCP response inspection ---
        mcp_findings = self._tool_detector.detect_mcp_traffic(body_json, headers_dict)
        if mcp_findings:
            self._mcp_traffic_found += len(mcp_findings)
            all_findings.extend(mcp_findings)

        # --- Deep analysis via Detection Service ---
        detection_result = None
        if all_findings or len(body_text) > 1000:
            detection_result = await call_detection_service(
                content=body_text,
                direction="response",
                content_type=headers_dict.get("content-type", ""),
                ai_service=service_name,
                request_url=flow.request.pretty_url,
                local_findings=all_findings,
            )

        # --- Determine action ---
        action_taken = self._determine_action(all_findings, detection_result)

        # --- Telemetry ---
        event = AITrafficEvent(
            event_id=str(uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_id=request_id,
            ai_service=service_name,
            category=category,
            direction="response",
            method=flow.request.method,
            url=flow.request.pretty_url,
            client_ip=client_ip,
            action_taken=action_taken,
            findings=all_findings,
            prompt_injection_detected=False,
            sensitive_data_detected=len(sensitive_findings) > 0,
            tool_calls_detected=len(tool_findings) > 0,
            mcp_traffic_detected=len(mcp_findings) > 0,
            exfiltration_risk=False,
            risk_score=self._compute_risk_score(all_findings, detection_result),
            detection_service_result=detection_result,
            tenant_id=TENANT_ID,
        )
        await emit_ai_telemetry(event)

        # --- Enforce on response ---
        if action_taken == "block":
            self._blocked += 1
            reason = self._build_block_reason(all_findings)
            flow.response = http.Response.make(
                403,
                json.dumps({
                    "error": "ai_response_blocked",
                    "reason": reason,
                    "request_id": request_id,
                    "service": "aishields-ai-interceptor",
                }).encode("utf-8"),
                {
                    "Content-Type": "application/json",
                    "X-AIShields-Request-ID": request_id,
                    "X-AIShields-Action": "block",
                },
            )
            logger.warning(
                "ai_response_blocked request_id=%s service=%s reason=%s",
                request_id,
                service_name,
                reason,
            )
        elif action_taken == "warn":
            flow.response.headers["X-AIShields-AI-Warning"] = self._build_block_reason(all_findings)
            flow.response.headers["X-AIShields-AI-Service"] = service_name

    # ---- Decision logic ---------------------------------------------------

    def _determine_action(
        self,
        findings: List[Dict[str, Any]],
        detection_result: Optional[Dict[str, Any]],
    ) -> str:
        """Determine the enforcement action based on mode, findings, and detection result.

        In 'monitor' mode, always returns 'monitor' regardless of findings.
        In 'warn' mode, returns 'warn' if any findings exist.
        In 'block' mode, returns 'block' for high-risk findings, 'warn' for medium.
        """
        if self._action_mode == "monitor":
            return "monitor"

        # Check if the detection service escalated the action
        if detection_result:
            ds_action = detection_result.get("action")
            if ds_action == "block" and self._action_mode == "block":
                return "block"
            if ds_action == "warn":
                return "warn" if self._action_mode in ("warn", "block") else "monitor"

        if not findings:
            return "monitor"

        # Classify findings by severity
        has_high_risk = any(
            f.get("type") in ("prompt_injection", "exfiltration_risk")
            for f in findings
        )
        has_sensitive = any(
            f.get("type") == "sensitive_data"
            and f.get("data_type") in ("ssn", "credit_card", "private_key", "aws_key")
            for f in findings
        )

        if self._action_mode == "block" and (has_high_risk or has_sensitive):
            return "block"

        if self._action_mode in ("warn", "block") and findings:
            return "warn"

        return "monitor"

    def _compute_risk_score(
        self,
        findings: List[Dict[str, Any]],
        detection_result: Optional[Dict[str, Any]],
    ) -> float:
        """Compute a normalised risk score (0.0 - 1.0) from findings.

        This is a heuristic score. The Detection Service may provide its own
        authoritative score which takes precedence.
        """
        if detection_result and "risk_score" in detection_result:
            return float(detection_result["risk_score"])

        if not findings:
            return 0.0

        score = 0.0
        weights = {
            "prompt_injection": 0.35,
            "exfiltration_risk": 0.3,
            "sensitive_data": 0.25,
            "tool_call": 0.05,
            "mcp_traffic": 0.05,
        }
        for f in findings:
            ftype = f.get("type", "")
            score += weights.get(ftype, 0.02)

        return min(score, 1.0)

    def _build_block_reason(self, findings: List[Dict[str, Any]]) -> str:
        """Build a human-readable block reason from findings."""
        types_found = sorted({f.get("type", "unknown") for f in findings})
        return f"ai_inspection_findings: {', '.join(types_found)}"


# ---------------------------------------------------------------------------
# Addon registration
# ---------------------------------------------------------------------------
addons = [AIInterceptorAddon()]
