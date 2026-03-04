"""
AIShields Protect - Microsoft Sentinel Output

Sends normalized security events to Microsoft Sentinel via the Azure
Log Analytics Data Collector API (also known as the HTTP Data Collector API).

Authentication uses workspace ID and shared key (primary or secondary).
Events are written to a custom log type (default: AIShieldsProtect_CL).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import logging
from typing import Any

import httpx

from outputs.base import SIEMOutput

logger = logging.getLogger("siem-connector.outputs.sentinel")

# Azure Monitor HTTP Data Collector API version
_API_VERSION = "2016-04-01"


class SentinelOutput(SIEMOutput):
    """Microsoft Sentinel output via Azure Log Analytics Data Collector API."""

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _validate_config(self) -> None:
        self._require_config("SENTINEL_WORKSPACE_ID", "SENTINEL_SHARED_KEY")

    @property
    def _workspace_id(self) -> str:
        return self._config["SENTINEL_WORKSPACE_ID"]

    @property
    def _shared_key(self) -> str:
        return self._config["SENTINEL_SHARED_KEY"]

    @property
    def _log_type(self) -> str:
        return self._config.get("SENTINEL_LOG_TYPE", "AIShieldsProtect")

    @property
    def _endpoint(self) -> str:
        """Build the Data Collector endpoint URL.

        Supports Azure Government via an optional config override.
        """
        base = self._config.get("SENTINEL_ENDPOINT")
        if base:
            return base.rstrip("/")
        return (
            f"https://{self._workspace_id}.ods.opinsights.azure.com"
        )

    @property
    def _resource_uri(self) -> str:
        return f"/api/logs?api-version={_API_VERSION}"

    # ------------------------------------------------------------------
    # Signature generation (HMAC-SHA256)
    # ------------------------------------------------------------------

    def _build_signature(
        self, body: str, rfc1123_date: str, content_length: int
    ) -> str:
        """Build the HMAC-SHA256 authorization signature required by the API.

        The string-to-sign format is:
            POST\n{content_length}\napplication/json\nx-ms-date:{date}\n/api/logs
        """
        string_to_sign = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{rfc1123_date}\n/api/logs"
        )
        decoded_key = base64.b64decode(self._shared_key)
        encoded_hash = base64.b64encode(
            hmac.new(
                decoded_key,
                string_to_sign.encode("utf-8"),
                digestmod=hashlib.sha256,
            ).digest()
        ).decode("utf-8")

        return f"SharedKey {self._workspace_id}:{encoded_hash}"

    # ------------------------------------------------------------------
    # Event transformation
    # ------------------------------------------------------------------

    def _transform_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Map a normalized AIShields event to a Sentinel-friendly document.

        The Data Collector API stores all fields as custom columns.  We
        flatten nested ``details`` into top-level keys with a ``detail_``
        prefix so they appear as searchable columns in Log Analytics.
        """
        doc: dict[str, Any] = {
            "EventId": event.get("event_id", ""),
            "TimeGenerated": event.get("timestamp", ""),
            "IngestedAt": event.get("ingested_at", ""),
            "TenantId_CF": event.get("tenant_id", ""),
            "SourceService": event.get("source_service", ""),
            "EventType": event.get("event_type", ""),
            "Severity": event.get("severity", ""),
            "SeverityNumeric": event.get("severity_numeric", 0),
            "Title": event.get("title", ""),
            "Description": event.get("description", ""),
            "Tags": ",".join(event.get("tags", [])),
            "Product": event.get("product", "AIShields Protect"),
            "ProductVersion": event.get("product_version", ""),
            "SchemaVersion": event.get("schema_version", ""),
        }

        # Flatten details dict
        details = event.get("details") or {}
        for key, value in details.items():
            safe_key = f"detail_{key}"
            doc[safe_key] = json.dumps(value) if isinstance(value, (dict, list)) else value

        return doc

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    async def send_event(self, event: dict[str, Any]) -> None:
        await self.send_batch([event])

    async def send_batch(self, events: list[dict[str, Any]]) -> None:
        """Send events to the Data Collector API as a JSON array.

        The API accepts up to 30 MB per POST.  We do *not* chunk here;
        the upstream batch-size configuration keeps payloads reasonable.
        """
        documents = [self._transform_event(e) for e in events]
        body = json.dumps(documents)
        content_length = len(body)

        rfc1123_date = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        signature = self._build_signature(body, rfc1123_date, content_length)

        headers = {
            "Content-Type": "application/json",
            "Authorization": signature,
            "Log-Type": self._log_type,
            "x-ms-date": rfc1123_date,
            "time-generated-field": "TimeGenerated",
        }

        url = f"{self._endpoint}{self._resource_uri}"

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=headers, content=body)
            if resp.status_code not in (200, 202):
                logger.error(
                    "Sentinel Data Collector API returned %d: %s",
                    resp.status_code,
                    resp.text,
                )
                raise ConnectionError(
                    f"Sentinel API error {resp.status_code}: {resp.text}"
                )
            logger.info(
                "Sent %d events to Sentinel workspace %s (log type %s)",
                len(events),
                self._workspace_id,
                self._log_type,
            )

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    async def test_connection(self) -> bool:
        """Verify credentials by posting an empty batch.

        If the workspace ID and shared key are valid the API returns 200.
        """
        try:
            test_doc = [
                {
                    "EventId": "connection-test",
                    "Title": "AIShields Sentinel connectivity test",
                    "TimeGenerated": datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat(),
                }
            ]
            body = json.dumps(test_doc)
            content_length = len(body)
            rfc1123_date = datetime.datetime.now(
                datetime.timezone.utc
            ).strftime("%a, %d %b %Y %H:%M:%S GMT")
            signature = self._build_signature(body, rfc1123_date, content_length)

            headers = {
                "Content-Type": "application/json",
                "Authorization": signature,
                "Log-Type": self._log_type,
                "x-ms-date": rfc1123_date,
                "time-generated-field": "TimeGenerated",
            }
            url = f"{self._endpoint}{self._resource_uri}"

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, headers=headers, content=body)
                return resp.status_code in (200, 202)
        except Exception as exc:
            logger.warning("Sentinel connectivity test failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    @classmethod
    def get_config_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "required": ["SENTINEL_WORKSPACE_ID", "SENTINEL_SHARED_KEY"],
            "properties": {
                "SENTINEL_WORKSPACE_ID": {
                    "type": "string",
                    "description": "Azure Log Analytics workspace ID (GUID).",
                },
                "SENTINEL_SHARED_KEY": {
                    "type": "string",
                    "description": (
                        "Primary or secondary shared key for the workspace."
                    ),
                },
                "SENTINEL_LOG_TYPE": {
                    "type": "string",
                    "description": (
                        "Custom log type name (default: AIShieldsProtect). "
                        "Sentinel appends '_CL' automatically."
                    ),
                },
                "SENTINEL_ENDPOINT": {
                    "type": "string",
                    "description": (
                        "Override the Data Collector endpoint "
                        "(e.g. for Azure Government)."
                    ),
                },
            },
        }
