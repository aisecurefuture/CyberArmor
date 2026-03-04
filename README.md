# AIShields Protect

**Enterprise AI Security Platform** — Comprehensive protection for organizations deploying AI, Agentic AI, and LLM-powered applications.

## Overview

AIShields Protect is a zero-trust, multi-layered security platform that provides real-time monitoring, policy enforcement, data loss prevention, and compliance management for enterprise AI workloads. Built with FIPS 140-3 and CNSA 2.0+ post-quantum cryptography throughout.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Admin Dashboard                          │
│                    (Vanilla JS SPA + Nginx)                     │
├─────────────────────────────────────────────────────────────────┤
│                       Ingress / Load Balancer                   │
├────────┬────────┬────────┬────────┬────────┬────────┬──────────┤
│Control │ Policy │Detect- │Response│Identity│  SIEM  │Compliance│
│ Plane  │ Engine │  ion   │        │Provider│Connector│ Engine  │
│ :8000  │ :8001  │ :8002  │ :8003  │ :8004  │ :8005  │ :8006   │
├────────┴────────┴────────┴────────┴────────┴────────┴──────────┤
│                   Transparent AI Proxy (:8010)                  │
│               (mitmproxy dev / Envoy production)                │
├─────────────────────────────────────────────────────────────────┤
│   PostgreSQL              Redis              Message Queue      │
├──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ Endpoint │ Browser  │   IDE    │ Office   │   RASP Agents       │
│  Agent   │Extensions│Extensions│ Add-ins  │  (9 languages)      │
├──────────┼──────────┼──────────┼──────────┼─────────────────────┤
│  macOS   │ Chrome   │ VS Code  │  Word    │  Java  │  .NET     │
│ Windows  │ Firefox  │ Visual   │  Excel   │ Python │  Node.js  │
│  Linux   │  Safari  │  Studio  │ PowerPt  │   Go   │  Rust     │
│          │   Edge   │  Cursor  │ OneNote  │  Ruby  │  PHP      │
│          │  Brave   │   Kiro   │ Outlook  │  C/C++ │           │
├──────────┴──────────┴──────────┴──────────┴────────┴───────────┤
│  Kernel: Linux eBPF │ macOS Endpoint Security │ Windows WFP    │
├─────────────────────┴────────────────────────┴─────────────────┤
│  ROS2 Agent (Robotics)  │  React Native Mobile (iOS/Android)   │
└─────────────────────────┴──────────────────────────────────────┘
```

## Core Services

| Service | Port | Description |
|---------|------|-------------|
| Control Plane | 8000 | Central API gateway, tenant management, API key CRUD |
| Policy Engine | 8001 | Extensible AND/OR policy evaluation, priority-based rules |
| Detection | 8002 | Prompt injection, jailbreak, toxicity, PII detection |
| Response | 8003 | Incident management, automated response actions |
| Identity Provider | 8004 | SSO integration (Entra ID, Okta, Ping, AWS IAM) |
| SIEM Connector | 8005 | Output to Splunk, Sentinel, QRadar, Elastic, Google SecOps, Syslog/CEF |
| Compliance Engine | 8006 | 14 compliance frameworks with evidence-based assessment |
| Transparent Proxy | 8010 | AI traffic interception, inspection, and policy enforcement |

## Security Features

- **Post-Quantum Cryptography**: ML-KEM-1024 (Kyber) key encapsulation, ML-DSA-87 (Dilithium) signing
- **PQC API Key Transport**: `PQC:<base64>` header format with AES-256-GCM encryption
- **Zero Trust Architecture**: All inter-service communication authenticated
- **Multi-Tenant**: Complete tenant isolation across all services
- **FIPS 140-3 Compliant**: Validated cryptographic modules
- **CNSA 2.0+ Ready**: Post-quantum algorithm suite

## Compliance Frameworks (14)

| Framework | Controls | Description |
|-----------|----------|-------------|
| NIST CSF 2.0 | 18 | Cybersecurity Framework |
| NIST 800-53 r5 | 20 | Security and Privacy Controls |
| NIST AI RMF | 17 | AI Risk Management Framework |
| CMMC Level 3 | 16 | Cybersecurity Maturity Model |
| NYDFS 23 NYCRR 500 | 15 | NY Financial Services Cybersecurity |
| ISO 27001:2022 | 18 | Information Security Management |
| CIS Controls v8 | 16 | Center for Internet Security |
| CSA CCM v4 | 16 | Cloud Security Alliance |
| OWASP (Combined) | 19 | Web + API + LLM Top 10 2025 + Agentic AI |
| SANS Top 25 | 15 | Most Dangerous Software Weaknesses |
| PCI-DSS v4.0 | 17 | Payment Card Industry |
| SOC 2 | 19 | Trust Services Criteria |
| GDPR | 16 | EU General Data Protection |
| CCPA/CPRA | 14 | California Consumer Privacy |

## Quick Start

### Docker Compose (Development)

```bash
cd infra/docker-compose
cp .env.example .env
# Edit .env with your configuration
docker-compose up -d
```

Access the admin dashboard at `http://localhost:3000`

### Smoke Test

```bash
# Start stack + run validation
./scripts/smoke-test.sh --up

# Run validation only (stack already running)
./scripts/smoke-test.sh
```

### Kubernetes / Helm (Production)

```bash
cd infra/helm/aishields
# Edit values.yaml for your environment
helm install aishields . -n aishields --create-namespace
```

### Endpoint Agent

```bash
cd agents/endpoint-agent
pip install -r requirements.txt
sudo python installer.py install --server https://your-aishields-server --api-key YOUR_KEY
```

## Project Structure

```
ai-protect-system-claude-4.6/
├── admin-dashboard/          # Vanilla JS admin SPA (16 views)
├── agents/
│   ├── endpoint-agent/       # Cross-platform endpoint security agent
│   │   ├── crypto/           # PQC key transport & signing
│   │   ├── dlp/              # Data loss prevention scanner
│   │   ├── monitors/         # Process, network, file, AI tool monitors
│   │   ├── platform/         # macOS, Windows, Linux integrations
│   │   └── zero_day/         # RCE guard & sandbox
│   ├── proxy-agent/          # mitmproxy-based transparent proxy
│   └── ros-agent/            # ROS2 robotics security agent
├── extensions/
│   ├── chromium-shared/      # Shared Chrome/Brave/Edge extension (MV3)
│   ├── edge/                 # Edge-specific manifest
│   ├── firefox/              # Firefox extension (MV2)
│   ├── safari/               # Safari Web Extension
│   ├── vscode/               # VS Code extension (TypeScript)
│   ├── visual-studio/        # Visual Studio extension (C#)
│   ├── cursor/               # Cursor IDE extension
│   ├── kiro/                 # Kiro IDE extension
│   └── office365/            # Office 365 add-in (Word, Excel, PPT, OneNote, Outlook)
├── infra/
│   ├── docker-compose/       # Docker Compose for local development
│   ├── envoy/                # Envoy proxy config + Lua filter
│   └── helm/aishields/       # Kubernetes Helm chart
├── kernel/
│   ├── linux/                # eBPF monitoring programs
│   ├── macos/                # Endpoint Security system extension
│   └── windows/              # Minifilter + WFP driver
├── libs/
│   └── aishields-core/       # Shared PQC crypto library
├── mobile/                   # React Native iOS/Android app
├── rasp/                     # Runtime Application Self-Protection
│   ├── java/                 # Java agent (javaagent)
│   ├── dotnet/               # .NET middleware
│   ├── python/               # Python WSGI/ASGI middleware
│   ├── nodejs/               # Node.js express/koa middleware
│   ├── go/                   # Go http.RoundTripper wrapper
│   ├── rust/                 # Rust inspector
│   ├── ruby/                 # Ruby Rack/Faraday middleware
│   ├── php/                  # PHP PSR-15/Laravel middleware
│   └── c_cpp/                # C/C++ LD_PRELOAD interceptor
└── services/
    ├── compliance/           # Compliance engine (14 frameworks)
    ├── identity/             # Identity provider service
    ├── policy/               # Policy engine with AND/OR groups
    ├── proxy/                # Transparent proxy core
    ├── siem-connector/       # SIEM output integrations
    └── [control-plane, detection, response in Archive]
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CONTROL_PLANE_URL` | Control plane service URL | `http://control-plane:8000` |
| `POLICY_API_SECRET` | Policy service API key | (required) |
| `DETECTION_API_SECRET` | Detection service API key | (required) |
| `POSTGRES_URL` | PostgreSQL connection string | `postgresql://...` |
| `REDIS_URL` | Redis connection string | `redis://redis:6379` |
| `PQC_ENABLED` | Enable post-quantum crypto | `true` |
| `FIPS_MODE` | Enable FIPS 140-3 mode | `true` |
| `LOG_LEVEL` | Logging level | `INFO` |

### Identity Provider Setup

See [docs/azure-app-registration.md](docs/azure-app-registration.md) for Microsoft Entra ID setup instructions.

## RASP Integration

Each RASP agent intercepts AI API calls at the application layer:

```python
# Python example
import aishields_rasp
aishields_rasp.init(server="https://your-server", api_key="YOUR_KEY")

# Automatically intercepts requests/httpx calls to AI endpoints
```

```javascript
// Node.js example
const aishields = require('@aishields/rasp');
aishields.init({ server: 'https://your-server', apiKey: 'YOUR_KEY' });
// Automatically patches http/https modules
```

```go
// Go example
import "github.com/aishields/rasp"
client := &http.Client{Transport: rasp.NewTransport(http.DefaultTransport, config)}
```

## Development

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker & Docker Compose
- (Optional) Kubernetes cluster with Helm 3

### Running Services Locally

```bash
# Start infrastructure
docker-compose -f infra/docker-compose/docker-compose.yml up -d postgres redis

# Start individual services
cd services/policy && pip install -r requirements.txt && uvicorn main:app --port 8001
cd services/compliance && uvicorn main:app --port 8006
```

### Running Tests

```bash
# Shared crypto library
cd libs/aishields-core && python -m pytest tests/

# Policy engine
cd services/policy && python -m pytest

# Compliance frameworks
cd services/compliance && python -m pytest
```

## License

Proprietary - AIShields Inc. All rights reserved.

## Support

- Enterprise Support: support@gratitech.com
- Security Issues: security@gratitech.com
