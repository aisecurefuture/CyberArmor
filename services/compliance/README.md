# AIShields Compliance Engine

Evidence-based compliance assessment engine supporting 14 regulatory and security frameworks.

## Features

- **14 Compliance Frameworks**: NIST CSF, 800-53, AI RMF, CMMC, NYDFS, ISO 27001, CIS, CSA CCM, OWASP, SANS, PCI-DSS, SOC 2, GDPR, CCPA
- **Evidence-Based Assessment**: Automated evaluation against submitted evidence
- **Real-Time Scoring**: Per-control PASS/FAIL/PARTIAL with overall compliance percentages
- **Multi-Tenant**: Tenant-scoped assessments and evidence storage
- **Extensible**: Decorator-based framework registration for custom frameworks
- **AI-Specific Controls**: NIST AI RMF, OWASP LLM Top 10 2025, Agentic AI controls

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/frameworks` | List all available frameworks |
| GET | `/frameworks/{id}/controls` | Get controls for a specific framework |
| POST | `/assess/{tenant_id}` | Run assessment against selected frameworks |
| GET | `/assess/{tenant_id}/report` | Get latest assessment report |
| POST | `/evidence/{tenant_id}` | Submit evidence for assessment |
| GET | `/evidence/{tenant_id}` | Retrieve submitted evidence |
| GET | `/health` | Health check |

## Running

```bash
pip install fastapi uvicorn
uvicorn main:app --host 0.0.0.0 --port 8006
```

## Assessment Example

```bash
# Submit evidence
curl -X POST http://localhost:8006/evidence/tenant-1 \
  -H "x-api-key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "encryption_at_rest": true,
    "mfa_enabled": true,
    "siem_enabled": true,
    "incident_response_plan": true,
    "ai_inventory": true,
    "prompt_injection_detection": true
  }'

# Run assessment
curl -X POST http://localhost:8006/assess/tenant-1 \
  -H "x-api-key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"frameworks": ["nist_csf", "owasp", "nist_ai_rmf"]}'
```

## Adding Custom Frameworks

```python
from frameworks.base import ComplianceFramework, Control
from frameworks import register

@register
class MyFramework(ComplianceFramework):
    id = "my_framework"
    name = "My Custom Framework"
    version = "1.0"

    def get_controls(self):
        return [
            Control(
                id="MF-1",
                title="Custom Control",
                description="Description of the control",
                category="Security",
                evidence_keys=["custom_evidence_key"]
            )
        ]
```
