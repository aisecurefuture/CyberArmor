# CyberArmor — AI Identity Control Plane

> **"Okta for AI Agents"** — Zero-trust identity, policy enforcement, and immutable audit for every AI interaction in your enterprise.

---

## Overview

CyberArmor is the enterprise-grade **AI Identity Control Plane** — the security and governance layer that sits between your applications and every AI provider, agent, and framework. It answers the fundamental zero-trust question for AI:

> *"Which agent is making this request, is it allowed to do so, and was it audited?"*

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Your Application / AI Workflow                       │
│   LangChain │ LlamaIndex │ Vercel AI │ Direct SDK │ Custom Agent        │
└──────────────────────────┬──────────────────────────────────────────────┘
                           │  SDK (9 languages)
                           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    CyberArmor AI Identity Control Plane                  │
│                                                                          │
│  ┌────────────────┐  ┌─────────────────┐  ┌──────────────────────────┐ │
│  │ Agent Identity │  │  Policy Engine  │  │   Audit & Action Graph   │ │
│  │  Service :8008 │  │  (AI-aware PDP) │  │      Service :8011       │ │
│  │                │  │      :8001      │  │                          │ │
│  │ • JWT issuance │  │ • ALLOW         │  │ • HMAC-signed events     │ │
│  │ • SPIFFE attest│  │ • DENY          │  │ • Directed action graph  │ │
│  │ • Delegations  │  │ • REDACT        │  │ • Trace correlation      │ │
│  │ • Token revoke │  │ • LIMITS        │  │ • Risk scoring           │ │
│  └────────────────┘  │ • APPROVE       │  └──────────────────────────┘ │
│                      │ • AUDIT_ONLY    │                                │
│  ┌────────────────┐  │ • QUARANTINE    │  ┌──────────────────────────┐ │
│  │   AI Router    │  └─────────────────┘  │   Admin Dashboard :3000  │ │
│  │   :8009        │                        │                          │ │
│  │                │  ┌─────────────────┐  │ • Agent Directory        │ │
│  │ • 8 providers  │  │   DLP + Detect  │  │ • AI Provider Mgmt       │ │
│  │ • Credential   │  │   :8002 / PQC   │  │ • Policy Studio          │ │
│  │   vault        │  │                 │  │ • Action Graph           │ │
│  │ • Cost tracking│  │ • Prompt inject │  │ • AI Risk Dashboard      │ │
│  │ • Fernet enc.  │  │ • PII scanning  │  │ • Delegation Manager     │ │
│  └────────────────┘  └─────────────────┘  │ • SDK & Onboarding       │ │
│                                            └──────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
        ┌──────────────────────────────────────┐
        │           AI Providers               │
        │  OpenAI │ Anthropic │ Google │ AWS   │
        │  Azure  │ xAI │ Meta │ Perplexity    │
        └──────────────────────────────────────┘
```

---

## Quick Start

### 1. Start the Stack

```bash
cd infra/docker-compose
docker compose up -d
```

Services started:
| Service | Port | Description |
|---|---|---|
| Control Plane | 8000 | API gateway + tenant management |
| Policy Engine | 8001 | AI-aware policy decision point |
| Detection | 8002 | Prompt injection + DLP |
| Response | 8003 | Incident response |
| **Agent Identity** | **8008** | **AI agent identity & tokens** |
| **AI Router** | **8009** | **Unified AI provider gateway** |
| **Audit Graph** | **8011** | **Immutable audit + action graph** |
| Dashboard | 3000 | Admin UI |

### 2. Register Your First Agent

```bash
curl -X POST http://localhost:8008/agents/register \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "my-org",
    "name": "my-first-agent",
    "trust_level": "standard",
    "capabilities": ["ai:inference", "ai:audit"],
    "max_requests_per_minute": 100
  }'
# Returns: { "agent_id": "agt_abc123...", "agent_secret": "..." }
```

### 3. Install the Python SDK

```bash
pip install cyberarmor-sdk[openai,anthropic]
```

### 4. Protect Your AI Calls

```python
import os
from cyberarmor import CyberArmorClient
from cyberarmor.providers import CyberArmorOpenAI

os.environ["CYBERARMOR_URL"]          = "http://localhost:8008"
os.environ["CYBERARMOR_AGENT_ID"]     = "agt_abc123..."
os.environ["CYBERARMOR_AGENT_SECRET"] = "<from registration>"

client = CyberArmorClient()
openai = CyberArmorOpenAI(cyberarmor_client=client)

# Exact same API as openai.OpenAI() — fully drop-in
response = openai.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Summarise this contract..."}]
)
```

Every call is now:
- ✅ **Identity-verified** — JWT asserted against agent registry
- ✅ **Policy-evaluated** — decision in <5ms p99
- ✅ **Audited** — HMAC-SHA256 signed event in the action graph
- ✅ **Risk-scored** — real-time risk dashboard updated

---

## Architecture

### New Services (AI Identity Control Plane)

#### Agent Identity Service (`:8008`)

Non-human AI agent identities as first-class citizens — like AWS IAM but for agents.

- **Agent Registration**: `POST /agents/register` — creates `agt_*` identities with capabilities, trust levels, and rate limits
- **Token Issuance**: `POST /agents/{id}/tokens/issue` — short-lived JWT access tokens with scoped capabilities
- **Workload Attestation**: `POST /workloads/attest` — SPIFFE/SPIRE-compatible attestation for Kubernetes pods
- **Delegation Chains**: `POST /delegations` — hierarchical agent-to-agent authority delegation with `del_*` chain IDs
- **Token Revocation**: Instant revocation via Redis-backed CRL

#### AI Provider Router (`:8009`)

Unified gateway to all 8 AI providers. One endpoint, any model.

- **Providers**: OpenAI, Anthropic, Google AI, Amazon Bedrock, Microsoft Azure OpenAI, xAI Grok, Meta LLaMA (via Together/Fireworks/Ollama), Perplexity
- **Credential Vault**: Provider API keys encrypted with Fernet symmetric encryption
- **Credential Rotation**: `POST /credentials/providers/{provider}/rotate` — zero-downtime key rotation
- **Cost Tracking**: Per-request token cost estimation with monthly budget enforcement
- **Model Routing**: Automatic provider selection from model name

#### Audit & Action Graph Service (`:8011`)

Immutable, signed audit trail with graph-based lineage tracking.

- **Signed Events**: Every event HMAC-SHA256 signed — tamper-evident audit trail
- **Action Graph**: Directed graph (agents → models → tools → humans) with full lineage
- **Trace Correlation**: Distributed tracing with `trace_id` / `span_id`
- **Integrity Verification**: `GET /integrity/verify/{event_id}` — cryptographic proof of event authenticity
- **Export**: JSON/CSV export with configurable date ranges

### Existing Services (enhanced)

- **Policy Engine (`:8001`)**: Extended with `ai_decision_type` (7 decision types), `ai_providers` restrictions, `risk_score` thresholds
- **Detection (`:8002`)**: 14 prompt injection patterns, 8 DLP patterns (SSN, CC, API keys, JWT, AWS keys, etc.)
- **Control Plane (`:8000`)**: PQC (ML-KEM-1024 + ML-DSA-87) encrypted API key management

---

## SDK Reference

### Supported Languages

| Language | Package | Install |
|---|---|---|
| **Python** | `cyberarmor-sdk` | `pip install cyberarmor-sdk[openai,anthropic]` |
| **Node.js/TS** | `@cyberarmor/sdk` | `npm install @cyberarmor/sdk` |
| **Go** | `cyberarmor-go` | `go get github.com/cyberarmor-ai/cyberarmor-go` |
| **.NET/C#** | `CyberArmor.SDK` | `dotnet add package CyberArmor.SDK` |
| **Java** | `ai.cyberarmor:cyberarmor-sdk` | Maven/Gradle |
| **Ruby** | `cyberarmor-sdk` | `gem install cyberarmor-sdk` |
| **PHP** | `cyberarmor/sdk` | `composer require cyberarmor/sdk` |
| **Rust** | `cyberarmor-sdk` | `cargo add cyberarmor-sdk` |
| **C/C++** | `libcyberarmor` | CMake / Conan / vcpkg |

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `CYBERARMOR_URL` | Agent Identity Service URL | `http://localhost:8008` |
| `CYBERARMOR_AGENT_ID` | Registered agent ID (`agt_*`) | — |
| `CYBERARMOR_AGENT_SECRET` | Agent shared secret | — |
| `CYBERARMOR_ENFORCE_MODE` | `enforce` / `monitor` / `off` | `enforce` |
| `CYBERARMOR_FAIL_OPEN` | Allow if control plane unreachable | `false` |
| `CYBERARMOR_AUDIT_URL` | Audit Graph Service URL | `http://localhost:8011` |
| `CYBERARMOR_ROUTER_URL` | AI Router URL | `http://localhost:8009` |
| `CYBERARMOR_URL` | Legacy alias (backward compat.) | — |

### AI Provider Support

```python
from cyberarmor.providers import (
    CyberArmorOpenAI,       # OpenAI — drop-in for openai.OpenAI
    CyberArmorAnthropic,    # Anthropic — drop-in for anthropic.Anthropic
    CyberArmorGoogleAI,     # Google AI — wraps GenerativeModel
    CyberArmorBedrock,      # AWS Bedrock — wraps boto3 bedrock-runtime
    CyberArmorAzureOpenAI,  # Azure OpenAI
    CyberArmorXAI,          # xAI Grok (OpenAI-compatible)
    CyberArmorPerplexity,   # Perplexity (OpenAI-compatible)
    CyberArmorMeta,         # Meta LLaMA via Together/Fireworks/Ollama
)
```

### Framework Integrations

```python
# LangChain
from cyberarmor.frameworks.langchain import CyberArmorCallbackHandler
handler = CyberArmorCallbackHandler(client=client)
llm = ChatOpenAI(callbacks=[handler])

# LlamaIndex (global instrumentation)
from cyberarmor.frameworks.llamaindex import CyberArmorInstrumentation
CyberArmorInstrumentation.patch_all(client)

# FastAPI middleware
from cyberarmor.middleware.fastapi import CyberArmorMiddleware
app.add_middleware(CyberArmorMiddleware, client=client)
```

```typescript
// Node.js / TypeScript
import { CyberArmorOpenAI } from "@cyberarmor/sdk/providers/openai";
import { CyberArmorCallbackHandler } from "@cyberarmor/sdk/frameworks/langchain";

// Vercel AI SDK
import { CyberArmorLanguageModel } from "@cyberarmor/sdk/vercel";
import { openai } from "@ai-sdk/openai";
const model = new CyberArmorLanguageModel({ client, model: openai("gpt-4o") });
```

---

## Policy Decision Types

The AI-aware policy engine supports 7 granular decision types:

| Decision | Behavior |
|---|---|
| `ALLOW` | Request proceeds normally |
| `DENY` | Request blocked; `PolicyViolationError` raised |
| `ALLOW_WITH_REDACTION` | PII/sensitive data redacted from prompt before forwarding |
| `ALLOW_WITH_LIMITS` | Rate limiting or token budget applied |
| `REQUIRE_APPROVAL` | Async human-in-the-loop approval required |
| `ALLOW_WITH_AUDIT_ONLY` | Allowed but flagged for enhanced audit scrutiny |
| `QUARANTINE` | Response quarantined pending security review |

---

## CLI Reference

```bash
pip install cyberarmor-sdk[cli]

# Agent management
cyberarmor agents list --tenant my-org
cyberarmor agents register --name finance-bot --trust-level privileged
cyberarmor tokens issue agt_abc123 --scopes ai:inference,ai:audit --expires 1h

# Provider management
cyberarmor providers list
cyberarmor providers configure openai --api-key sk-... --budget 500

# Audit & observability
cyberarmor audit events --tenant my-org --limit 50
cyberarmor audit graph --agent agt_abc123

# Delegations
cyberarmor delegations create --from agt_supervisor --to agt_worker --scopes ai:inference --expires 24h

# Health check all services
cyberarmor health
```

---

## Admin Dashboard

Open [http://localhost:3000](http://localhost:3000) to access the full Admin Dashboard.

**AI Identity Control Plane views:**
- 🤖 **Agent Directory** — Register, inspect, issue tokens, revoke agents
- ⚡ **AI Providers** — Configure and test all 8 AI provider credentials
- 🎯 **Policy Studio** — AI-aware policy management with risk score visualization
- 🕸️ **Action Graph** — Real-time SVG visualization of agent → model → tool interactions
- ⚠️ **AI Risk Dashboard** — Per-agent risk scores, blocked actions, recommendations
- 🔗 **Delegation Manager** — Create and revoke agent delegation chains
- 📦 **SDK & Onboarding** — Install snippets, quickstart code, API reference

---

## Security Architecture

### Post-Quantum Cryptography

All key operations use:
- **ML-KEM-1024** (Kyber) — post-quantum key encapsulation
- **ML-DSA-87** (Dilithium) — post-quantum digital signatures
- Fallback to **Ed25519** when `liboqs` is unavailable

### Zero-Trust Principles Applied to AI

1. **Never trust any agent** — every AI agent must authenticate with a short-lived JWT
2. **Verify every request** — policy evaluated synchronously on every AI API call (<5ms p99)
3. **Assume breach** — every action logged with HMAC-signed, tamper-evident audit events
4. **Least privilege** — agents declare required capabilities at registration; requests to undeclared capabilities are denied

---

## Deployment

### Kubernetes (Helm)

```bash
helm install cyberarmor ./infra/helm/cyberarmor \
  --set agentIdentity.replicas=3 \
  --set aiRouter.replicas=3 \
  --set audit.replicas=2 \
  --set global.imageRegistry=ghcr.io/your-org
```

### Terraform (AWS EKS)

```bash
cd infra/terraform/environments/prod
terraform init
terraform apply \
  -var="eks_cluster_name=my-cluster" \
  -var="image_tag=2.0.0"
```

### Environment Variables for Production

Store all secrets in AWS SSM Parameter Store at paths:
```
/cyberarmor/prod/DATABASE_URL
/cyberarmor/prod/REDIS_URL
/cyberarmor/prod/JWT_SECRET
/cyberarmor/prod/HMAC_SECRET
/cyberarmor/prod/AI_ROUTER_FERNET_KEY
```

---

## Compliance

CyberArmor maps to 14 compliance frameworks:

| Framework | Coverage |
|---|---|
| NIST AI RMF | AI lifecycle governance, risk management |
| NIST CSF 2.0 | Identify, Protect, Detect, Respond, Recover |
| SOC 2 Type II | Access controls, audit logs, availability |
| ISO 27001 | Information security management |
| GDPR / CCPA | PII detection, data minimization, right-to-erasure |
| HIPAA | PHI protection in healthcare AI workflows |
| PCI-DSS | Payment card data protection |
| EU AI Act | High-risk AI system requirements |
| MITRE ATLAS | AI/ML attack mitigation |
| OWASP LLM Top 10 | Prompt injection, insecure output, excessive agency |
| FedRAMP | Federal cloud security requirements |
| CMMC | Defense contractor cybersecurity maturity |

---

## API Documentation

See [`/docs/api/openapi.yaml`](./docs/api/openapi.yaml) for the full OpenAPI 3.1.0 specification covering all three AI Identity Control Plane services.

Interactive documentation available at:
- Agent Identity: `http://localhost:8008/docs`
- AI Router: `http://localhost:8009/docs`
- Audit Graph: `http://localhost:8011/docs`

---

## License

Copyright © 2026 CyberArmor AI. All rights reserved.
