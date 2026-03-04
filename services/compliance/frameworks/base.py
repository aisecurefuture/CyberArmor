"""Base classes for compliance framework engine."""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class Control:
    """A single compliance control."""
    id: str
    name: str
    description: str
    category: str
    severity: str = "medium"  # critical, high, medium, low
    automated: bool = True
    evidence_keys: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """A compliance finding (pass or fail)."""
    control_id: str
    control_name: str
    status: str  # pass, fail, not_applicable, manual_review
    details: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""


@dataclass
class AssessmentResult:
    """Result of a compliance assessment."""
    framework_id: str
    framework_name: str
    version: str
    tenant_id: str
    timestamp: str = ""
    controls_assessed: int = 0
    controls_passed: int = 0
    controls_failed: int = 0
    controls_na: int = 0
    controls_manual: int = 0
    score_pct: float = 0.0
    findings: List[Finding] = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "framework_id": self.framework_id,
            "framework_name": self.framework_name,
            "version": self.version,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp,
            "controls_assessed": self.controls_assessed,
            "controls_passed": self.controls_passed,
            "controls_failed": self.controls_failed,
            "controls_na": self.controls_na,
            "controls_manual": self.controls_manual,
            "score_pct": self.score_pct,
            "findings": [
                {"control_id": f.control_id, "control_name": f.control_name,
                 "status": f.status, "details": f.details, "remediation": f.remediation}
                for f in self.findings
            ],
        }


class ComplianceFramework(ABC):
    """Abstract base for compliance frameworks."""

    framework_id: str = ""
    framework_name: str = ""
    version: str = ""

    @abstractmethod
    def get_controls(self) -> List[Control]:
        ...

    def assess(self, evidence: Dict[str, Any], tenant_id: str = "") -> AssessmentResult:
        controls = self.get_controls()
        result = AssessmentResult(
            framework_id=self.framework_id,
            framework_name=self.framework_name,
            version=self.version,
            tenant_id=tenant_id,
        )
        for ctrl in controls:
            finding = self._assess_control(ctrl, evidence)
            result.findings.append(finding)
            result.controls_assessed += 1
            if finding.status == "pass":
                result.controls_passed += 1
            elif finding.status == "fail":
                result.controls_failed += 1
            elif finding.status == "not_applicable":
                result.controls_na += 1
            else:
                result.controls_manual += 1

        assessed_applicable = result.controls_assessed - result.controls_na
        if assessed_applicable > 0:
            result.score_pct = round(result.controls_passed / assessed_applicable * 100, 1)
        return result

    def _assess_control(self, ctrl: Control, evidence: Dict[str, Any]) -> Finding:
        """Assess a single control against provided evidence."""
        if not ctrl.automated:
            return Finding(ctrl.id, ctrl.name, "manual_review", "Requires manual review")

        if not ctrl.evidence_keys:
            return Finding(ctrl.id, ctrl.name, "manual_review", "No automated evidence mapping")

        all_present = True
        details = []
        for key in ctrl.evidence_keys:
            val = evidence.get(key)
            if val is None or val is False or val == "":
                all_present = False
                details.append(f"Missing: {key}")
            elif val is True or (isinstance(val, str) and val.strip()):
                details.append(f"Present: {key}")

        status = "pass" if all_present else "fail"
        return Finding(
            ctrl.id, ctrl.name, status,
            details="; ".join(details),
            remediation=f"Ensure {', '.join(ctrl.evidence_keys)} are configured" if status == "fail" else "",
        )
