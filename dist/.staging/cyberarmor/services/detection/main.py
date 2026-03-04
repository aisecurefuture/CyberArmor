import logging
import os
import re
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("detection_service")

DETECTION_API_SECRET = os.getenv("DETECTION_API_SECRET", "change-me-detection")


class GenericScanRequest(BaseModel):
    content: str = ""
    direction: str = "request"
    content_type: str = "text/plain"
    source_url: Optional[str] = None
    tenant_id: str = "default"
    local_findings: List[Dict[str, Any]] = Field(default_factory=list)


class TextRequest(BaseModel):
    text: str


PROMPT_PATTERNS = [
    re.compile(r"ignore\\s+(all\\s+)?previous\\s+instructions", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"reveal\\s+(your|the)\\s+system\\s+prompt", re.IGNORECASE),
]

SENSITIVE_PATTERNS = [
    ("ssn", re.compile(r"\\b\\d{3}-\\d{2}-\\d{4}\\b")),
    ("credit_card", re.compile(r"\\b(?:4\\d{3}|5[1-5]\\d{2}|3[47]\\d{2}|6(?:011|5\\d{2}))[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b")),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
]

DANGEROUS_OUTPUT_PATTERNS = [
    re.compile(r"\\brm\\s+-rf\\b", re.IGNORECASE),
    re.compile(r"\\bcurl\\b.*\\|\\s*(?:bash|sh)", re.IGNORECASE),
    re.compile(r"powershell\\s+-enc", re.IGNORECASE),
]


def _verify_api_key(api_key: Optional[str]) -> None:
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if api_key != DETECTION_API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


def _scan_prompt_injection(text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for pattern in PROMPT_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append({
                "type": "prompt_injection",
                "pattern": pattern.pattern,
                "match": match.group(0)[:120],
                "severity": "high",
            })
    return findings


def _scan_sensitive_data(text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for name, pattern in SENSITIVE_PATTERNS:
        for match in pattern.finditer(text):
            findings.append({
                "type": "sensitive_data",
                "subtype": name,
                "match": match.group(0)[:120],
                "severity": "high" if name in {"private_key", "aws_key"} else "medium",
            })
    return findings


def _scan_output_safety(text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for pattern in DANGEROUS_OUTPUT_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append({
                "type": "dangerous_output",
                "pattern": pattern.pattern,
                "match": match.group(0)[:120],
                "severity": "high",
            })
    return findings


def _risk_score(findings: List[Dict[str, Any]]) -> float:
    if not findings:
        return 0.0
    score = 0.0
    for f in findings:
        sev = f.get("severity", "low")
        if sev == "high":
            score += 0.35
        elif sev == "medium":
            score += 0.2
        else:
            score += 0.1
    return min(score, 1.0)


app = FastAPI(title="CyberArmor.ai Detection Service", version="0.2.0")


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.2.0"}


@app.post("/scan")
def scan(payload: GenericScanRequest, x_api_key: Optional[str] = Header(default=None, alias="x-api-key")):
    _verify_api_key(x_api_key)
    text = payload.content or ""
    findings = list(payload.local_findings)
    findings.extend(_scan_prompt_injection(text))
    findings.extend(_scan_sensitive_data(text))
    findings.extend(_scan_output_safety(text))

    score = _risk_score(findings)
    action = "allow"
    reason = ""
    if score >= 0.7:
        action = "block"
        reason = "high_risk_content_detected"
    elif score >= 0.35:
        action = "warn"
        reason = "medium_risk_content_detected"

    return {
        "action": action,
        "reason": reason,
        "risk_score": score,
        "detections": findings,
        "tenant_id": payload.tenant_id,
        "direction": payload.direction,
    }


@app.post("/scan/prompt-injection")
def scan_prompt(payload: TextRequest, x_api_key: Optional[str] = Header(default=None, alias="x-api-key")):
    _verify_api_key(x_api_key)
    findings = _scan_prompt_injection(payload.text)
    return {"risk_score": _risk_score(findings), "detections": findings}


@app.post("/scan/sensitive-data")
def scan_sensitive(payload: TextRequest, x_api_key: Optional[str] = Header(default=None, alias="x-api-key")):
    _verify_api_key(x_api_key)
    findings = _scan_sensitive_data(payload.text)
    return {"risk_score": _risk_score(findings), "detections": findings}


@app.post("/scan/output-safety")
def scan_output(payload: TextRequest, x_api_key: Optional[str] = Header(default=None, alias="x-api-key")):
    _verify_api_key(x_api_key)
    findings = _scan_output_safety(payload.text)
    return {"risk_score": _risk_score(findings), "detections": findings}


@app.post("/scan/all")
def scan_all(payload: TextRequest, x_api_key: Optional[str] = Header(default=None, alias="x-api-key")):
    _verify_api_key(x_api_key)
    findings: List[Dict[str, Any]] = []
    findings.extend(_scan_prompt_injection(payload.text))
    findings.extend(_scan_sensitive_data(payload.text))
    findings.extend(_scan_output_safety(payload.text))
    return {"risk_score": _risk_score(findings), "detections": findings}
