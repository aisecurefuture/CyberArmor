# CyberArmor Admin Dashboard (static)

This dashboard is a **no-build** static UI that talks to the repo's existing microservices:

- Control Plane (FastAPI) — tenants, audit trail, API keys
- Policy Service (FastAPI) — policy CRUD
- Proxy Agent (FastAPI) — decisions + local blocklist
- Detection Service (FastAPI) — prompt/sensitive/output scanning
- Response Service (FastAPI) — incident orchestration

## Start the backend services

If you already have a docker-compose / infra script, start services normally.

Otherwise, you can run each service locally (example):
```bash
# Control plane
cd services/control-plane
pip install -r requirements.txt  # if you have one; otherwise install fastapi, uvicorn, sqlalchemy, pyjwt
uvicorn main:app --reload --port 8000

# Policy
cd ../policy
uvicorn main:app --reload --port 8001

# Detection
cd ../detection
uvicorn main:app --reload --port 8002

# Response
cd ../response
uvicorn main:app --reload --port 8003

# Proxy agent
cd ../../agents/proxy-agent
uvicorn main:app --reload --port 8010
```

## Open the dashboard

Serve the static files (any static server works). Example:
```bash
cd admin-dashboard
python -m http.server 5173
```

Then open: http://localhost:5173

## Configure

Use **Settings** in the sidebar to set service URLs + API keys:
- Control Plane key: env `CYBERARMOR_API_SECRET` (defaults to `change-me`)
- Policy key: env `POLICY_API_SECRET` (defaults to `change-me-policy`)
- Proxy key: env `PROXY_AGENT_API_SECRET` (defaults to `change-me-proxy`)

## Tenant scope

Set a tenant ID in the header to:
- filter audit logs
- edit policies for that tenant
- manage proxy blocks and run proxy decisions
