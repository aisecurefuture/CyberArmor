# CyberArmor.ai Detection Service

Content inspection service used by proxy, dashboard scan tools, and extensions.

## Endpoints
- `GET /health`
- `POST /scan` (proxy-compatible full scan)
- `POST /scan/prompt-injection`
- `POST /scan/sensitive-data`
- `POST /scan/output-safety`
- `POST /scan/all`

## Auth
All scan endpoints require header `x-api-key` matching `DETECTION_API_SECRET`.

## Run locally
```bash
pip install fastapi uvicorn[standard] pydantic
uvicorn main:app --host 0.0.0.0 --port 8002
```

## Environment
- `DETECTION_API_SECRET` (default `change-me-detection`)
