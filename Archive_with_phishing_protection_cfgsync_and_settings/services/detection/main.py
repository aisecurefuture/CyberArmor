import logging
import os
import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

# Make libs/aishields-core importable when running locally or in container.
LIB_PATH = Path(__file__).resolve().parent / "libs" / "aishields-core"
if LIB_PATH.exists():
    sys.path.append(str(LIB_PATH))

from aishields_core import (  # type: ignore
    OutputSafetyAnalyzer,
    PromptInjectionDetector,
    SensitiveDataDetector,
)

logger = logging.getLogger("detection_service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

prompt_detector = PromptInjectionDetector()
sensitive_detector = SensitiveDataDetector()
output_analyzer = OutputSafetyAnalyzer()

app = FastAPI(title="CyberArmor Detection Service", version="0.1.0")


class PromptScanRequest(BaseModel):
    text: str
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None


class OutputScanRequest(BaseModel):
    text: str


class SensitiveScanRequest(BaseModel):
    text: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan/prompt")
def scan_prompt(payload: PromptScanRequest):
    result = prompt_detector.detect(payload.text)
    logger.info(
        "prompt_scan tenant=%s user=%s score=%.2f indicators=%s",
        payload.tenant_id,
        payload.user_id,
        result.risk_score,
        result.matched_indicators,
    )
    return {
        "risk_score": result.risk_score,
        "matched_indicators": result.matched_indicators,
        "privacy_leak_risk": result.privacy_leak_risk,
        "reasoning": result.reasoning,
    }


@app.post("/scan/sensitive")
def scan_sensitive(payload: SensitiveScanRequest):
    result = sensitive_detector.detect(payload.text)
    return {"findings": result.findings, "redacted_text": result.redacted_text}


@app.post("/scan/output")
def scan_output(payload: OutputScanRequest):
    result = output_analyzer.analyze(payload.text)
    return {
        "risk_score": result.risk_score,
        "leak_indicators": result.leak_indicators,
        "dangerous_commands": result.dangerous_commands,
    }
