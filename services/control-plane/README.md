# AIShields Control Plane Service

Core tenant and API management service.

## Responsibilities
- Tenant CRUD (`/tenants`)
- API key management and auth context
- Telemetry ingestion (`/telemetry/ingest`)
- Audit log storage and retrieval (`/audit`)

## Run locally
```bash
pip install fastapi uvicorn[standard] pydantic sqlalchemy psycopg2-binary redis pyjwt
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Required environment variables
- `DATABASE_URL` (default: `sqlite:///./data/control_plane.db`)
- `CYBERARMOR_API_SECRET`
- `CYBERARMOR_JWT_SECRET`

## Notes
- Supports SQLite (dev) and PostgreSQL (prod).
- Writes best-effort audit records for every API call.
