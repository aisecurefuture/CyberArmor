# AIShields Response Service

Incident response orchestrator for dispatching mitigation actions.

## Responsibilities
- Accept incidents from detection/proxy/control-plane
- Execute response actions such as proxy block and webhook notification

## Endpoints
- `GET /health`
- `POST /respond`

## Run locally
```bash
pip install fastapi uvicorn[standard] pydantic httpx
uvicorn main:app --host 0.0.0.0 --port 8003
```

## Environment
- `PROXY_AGENT_URL` (default `http://proxy-agent:8010`)
- `RESPONSE_WEBHOOK_URL` (optional)
