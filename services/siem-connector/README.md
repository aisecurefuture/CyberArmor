# AIShields SIEM Connector

Multi-platform SIEM integration service for forwarding AI security events to enterprise security operations platforms.

## Supported SIEM Platforms

| Platform | Output Module | Protocol |
|----------|--------------|----------|
| Splunk | `splunk.py` | HEC (HTTP Event Collector) |
| Microsoft Sentinel | `sentinel.py` | Log Analytics Data Collector API |
| IBM QRadar | `qradar.py` | Syslog/LEEF + REST API |
| Elastic Security | `elastic.py` | Elasticsearch bulk API |
| Google SecOps (Chronicle) | `google_secops.py` | Ingestion API v2 |
| Syslog/CEF | `syslog_cef.py` | RFC 5424 Syslog + CEF format |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/events` | Submit security events for forwarding |
| POST | `/events/batch` | Batch submit events |
| GET | `/outputs` | List configured SIEM outputs |
| POST | `/outputs/{name}/configure` | Configure a SIEM output |
| POST | `/outputs/{name}/test` | Test SIEM connectivity |
| GET | `/health` | Health check |

## Event Format

Events follow the AIShields Common Event Format (ACEF):

```json
{
  "event_id": "uuid",
  "timestamp": "2025-01-15T10:30:00Z",
  "tenant_id": "tenant-1",
  "severity": "high",
  "category": "prompt_injection",
  "source": "proxy-agent",
  "description": "Prompt injection detected in API call to OpenAI",
  "details": {
    "model": "gpt-4",
    "endpoint": "api.openai.com",
    "user": "user@company.com",
    "action_taken": "blocked"
  }
}
```

## Configuration

```env
SIEM_API_SECRET=your-api-key
SPLUNK_HEC_URL=https://splunk.company.com:8088
SPLUNK_HEC_TOKEN=your-hec-token
SENTINEL_WORKSPACE_ID=your-workspace-id
SENTINEL_SHARED_KEY=your-shared-key
QRADAR_HOST=qradar.company.com
ELASTIC_HOSTS=https://elastic.company.com:9200
GOOGLE_SECOPS_PROJECT=your-gcp-project
SYSLOG_HOST=syslog.company.com
SYSLOG_PORT=514
```

## Running

```bash
pip install fastapi uvicorn aiohttp
uvicorn main:app --host 0.0.0.0 --port 8005
```

## Adding Custom SIEM Outputs

Extend `SIEMOutput` base class:

```python
from outputs.base import SIEMOutput

class CustomOutput(SIEMOutput):
    name = "custom_siem"

    async def configure(self, config: dict):
        self.endpoint = config["endpoint"]

    async def send(self, events: list):
        # Transform and send events
        pass

    async def test_connection(self) -> bool:
        # Verify connectivity
        return True
```
