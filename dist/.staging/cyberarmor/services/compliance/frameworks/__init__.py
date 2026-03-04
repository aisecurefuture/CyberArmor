"""Compliance frameworks registry."""

from .base import ComplianceFramework, Control, AssessmentResult, Finding

# Auto-discover frameworks
_REGISTRY = {}

def register(fw_class):
    """Decorator to register a framework."""
    _REGISTRY[fw_class.framework_id] = fw_class
    return fw_class

def get_framework(framework_id: str) -> ComplianceFramework:
    if framework_id not in _REGISTRY:
        raise ValueError(f"Unknown framework: {framework_id}")
    return _REGISTRY[framework_id]()

def list_frameworks():
    return [{"id": fid, "name": cls.framework_name, "version": cls.version} for fid, cls in _REGISTRY.items()]

# Import all frameworks to trigger registration
from . import (
    nist_csf, nist_800_53, nist_ai_rmf, cmmc_l3, nydfs,
    iso27001, cis_controls, csa_ccm, owasp, sans_top25,
    pci_dss, soc2, gdpr, ccpa,
)
