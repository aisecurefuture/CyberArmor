# Live Demo Script (10-12 Minutes)

This runbook is the fastest path to a stable, presenter-friendly CyberArmor demo.

## 1. Prep (2 min)

From repo root:

```bash
bash scripts/demo/run_live_demo.sh
```

Optional first-time build:

```bash
bash scripts/demo/run_live_demo.sh --build
```

What this does:
- Starts the stack in detached mode (avoids Compose monitor crash path)
- Runs HTTP/HTTPS proxy smoke checks
- Seeds telemetry, agent heartbeat, and a sample blocked incident
- Executes one runtime decision request for talking points

## 2. Demo Narrative (6-8 min)

Open `http://localhost:3000`.

### Slide/narration flow

1. **Overview**
- Message: "CyberArmor provides runtime AI security from endpoint to network."

2. **Telemetry (`#/telemetry`)**
- Show live event stream and metrics.
- Message: "This is real-time activity from agents and enforcement services."

3. **Incidents (`#/incidents`)**
- Confirm the seeded blocked incident is visible.
- Message: "Every policy decision is traceable to an incident object."

4. **Proxy controls (`#/proxy`)**
- Show cached proxy policy visibility and test URL action.
- Message: "Network egress can be governed at request time."

5. **Scan tools (`#/scan`)**
- Paste obvious prompt injection text and run scan.
- Message: "Detection catches prompt-injection style patterns before model execution."

6. **Compliance (`#/compliance`)**
- Show frameworks/evidence surfaces.
- Message: "Decisions become evidence, not just alerts."

## 3. Terminal Proof Points (2 min)

Run while presenting:

```bash
curl -v -x http://127.0.0.1:8080 http://example.com
curl -v -x http://127.0.0.1:8080 https://example.com
```

And:

```bash
docker compose -f infra/docker-compose/docker-compose.yml logs -f transparent-proxy
```

Message: "You can see policy inspection and forwarding in real time."

## 4. Backup Plan (if live services are noisy)

1. Re-seed only demo data:
```bash
bash scripts/demo/run_live_demo.sh --seed-only
```

2. Refresh:
- `http://localhost:3000/#/telemetry`
- `http://localhost:3000/#/incidents`

3. If proxy TLS noise appears (Apple/Zoom system traffic), keep focus on:
- `curl` smoke tests above
- Dashboard incident + telemetry proof

## 5. After Demo

```bash
docker compose -f infra/docker-compose/docker-compose.yml down
```
