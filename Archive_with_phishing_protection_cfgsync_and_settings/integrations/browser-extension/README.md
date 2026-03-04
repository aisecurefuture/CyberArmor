## Browser Extension Telemetry Contract

- **Endpoint**: `POST /telemetry/ingest` (Control Plane)
- **Headers**: `x-api-key` (control-plane API key), `x-tenant-id` (optional for dev), `Content-Type: application/json`
- **Body**:
  ```json
  {
    "tenant_id": "demo-tenant",
    "user_id": "optional-user",
    "event_type": "page_visit | form_detected | pii_detected | copy_paste | genai_detected | policy_violation",
    "payload": { "url": "...", "redacted_value": "...", "field": "..." },
    "source": "browser_extension",
    "occurred_at": "ISO-8601 timestamp"
  }
  ```
- **Expected responses**: 202 Accepted with `{ "status": "accepted" }` on success.
- **Privacy**: Client-side redaction before send; only redacted values or metadata should be transmitted.
- **Failure handling**: Extension logs but does not block the user if the endpoint is unreachable.
