# AISR: AI Security Runtime (CyberArmor / AIShields)

This repo already has the *building blocks* of an AI security platform (proxy, detection, policy, response, control plane, endpoint/RASP agents).

**AISR (AI Security Runtime)** is the productized, runtime layer that turns those blocks into a single, enterprise-buyable control surface.

## What AISR is
AISR is a **runtime decision + telemetry fabric** for AI usage across:
- **Endpoints** (AI tools, IDEs, browsers)
- **Applications** (RASP interceptors / SDKs)
- **Networks** (transparent proxy / gateway)
- **Robotics / OT** (ROS2 agent)

It enforces:
- *What AI can be used*
- *What data can be sent*
- *What outputs can be returned*
- *What actions must occur when a violation happens*

## The AISR control loop
1. **Observe**: capture AI requests/responses + metadata (process, user, app, repo, model)
2. **Decide**: detection + policy evaluation + risk scoring
3. **Act**: allow / redact / block / quarantine / notify / ticket
4. **Prove**: audit logging + compliance evidence

## Minimal AISR v1 (what to ship first)
- A single **runtime API** (gateway) that applications and the proxy can call:
  - `POST /runtime/evaluate` → returns `{decision, reasons, actions}`
- Unified **incident schema** (control plane) to store decisions/actions
- OTLP telemetry export for every decision (for SIEM/SOAR)

## Integration points in this repo
- `services/detection` → detectors (prompt injection / sensitive data / unsafe output)
- `services/policy` → policy evaluation and header-based enforcement
- `services/response` → action orchestration (block, notify, webhook)
- `services/control-plane` → API keys, audit log, tenanting
- `services/proxy` + `agents/proxy-agent` → enforce on network egress

## North-star differentiation (the sentence)
> AISR is the only runtime that protects AI **from kernel to cloud**, across **every language**, **every endpoint**, and **every AI tool**, with **PQC-ready crypto** and **compliance evidence built in**.

## Next implementation step
Create `services/runtime` as a thin orchestrator:
- calls detection
- calls policy
- calls response
- writes incident to control-plane

This keeps detectors/policies modular, while giving you a single product surface for buyers.
