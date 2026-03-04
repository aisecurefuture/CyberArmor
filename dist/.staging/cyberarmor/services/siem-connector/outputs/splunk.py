"""
CyberArmor.ai Protect - Splunk HEC Output

Sends normalized security events to Splunk via the HTTP Event Collector (HEC) API.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx

from outputs.base import SIEMOutput

logger = logging.getLogger("siem-connector.outputs.splunk")


class SplunkOutput(SIEMOutput):
    """Splunk HTTP Event Collector output adapter."""

    def _validate_config(self) -> None:
        self._require_config("SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN")

    @property
    def _hec_url(self) -> str:
        base = self._config["SPLUNK_HEC_URL"].rstrip("/")
        return f"{base}/services/collector/event"

    @property
    def _batch_url(self) -> str:
        base = self._config["SPLUNK_HEC_URL"].rstrip("/")
        return f"{base}/services/collector/event"

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Splunk {self._config['SPLUNK_HEC_TOKEN']}",
            "Content-Type": "application/json",
        }

    def _build_hec_payload(self, event: dict[str, Any]) -> dict[str, Any]:
        """Build a Splunk HEC JSON payload from a normalized event."""
        payload: dict[str, Any] = {
            "event": event,
            "time": time.time(),
            "host": "aishields-protect",
        }
        if self._config.get("SPLUNK_INDEX"):
            payload["index"] = self._config["SPLUNK_INDEX"]
        if self._config.get("SPLUNK_SOURCE"):
            payload["source"] = self._config["SPLUNK_SOURCE"]
        else:
            payload["source"] = "aishields:protect"
        if self._config.get("SPLUNK_SOURCETYPE"):
            payload["sourcetype"] = self._config["SPLUNK_SOURCETYPE"]
        else:
            payload["sourcetype"] = "_json"
        return payload

    async def send_event(self, event: dict[str, Any]) -> None:
        payload = self._build_hec_payload(event)
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            resp = await client.post(
                self._hec_url,
                headers=self._headers,
                content=json.dumps(payload),
            )
            if resp.status_code != 200:
                logger.error(
                    "Splunk HEC returned %d: %s", resp.status_code, resp.text
                )
                raise ConnectionError(
                    f"Splunk HEC error {resp.status_code}: {resp.text}"
                )
            logger.debug("Event sent to Splunk HEC: %s", event.get("event_id"))

    async def send_batch(self, events: list[dict[str, Any]]) -> None:
        """Send events as newline-delimited JSON (Splunk HEC batch mode)."""
        lines = []
        for event in events:
            payload = self._build_hec_payload(event)
            lines.append(json.dumps(payload))
        body = "\n".join(lines)

        async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
            resp = await client.post(
                self._batch_url,
                headers=self._headers,
                content=body,
            )
            if resp.status_code != 200:
                logger.error(
                    "Splunk HEC batch returned %d: %s", resp.status_code, resp.text
                )
                raise ConnectionError(
                    f"Splunk HEC batch error {resp.status_code}: {resp.text}"
                )
            logger.info("Batch of %d events sent to Splunk HEC", len(events))

    async def test_connection(self) -> bool:
        """Send a health check to the HEC endpoint."""
        health_url = self._config["SPLUNK_HEC_URL"].rstrip("/") + "/services/collector/health/1.0"
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                resp = await client.get(health_url, headers=self._headers)
                return resp.status_code == 200
        except Exception as exc:
            logger.warning("Splunk HEC connectivity test failed: %s", exc)
            return False

    @classmethod
    def get_config_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "required": ["SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN"],
            "properties": {
                "SPLUNK_HEC_URL": {
                    "type": "string",
                    "description": "Splunk HEC endpoint URL (e.g. https://splunk:8088)",
                },
                "SPLUNK_HEC_TOKEN": {
                    "type": "string",
                    "description": "Splunk HEC authentication token",
                },
                "SPLUNK_INDEX": {
                    "type": "string",
                    "description": "Target Splunk index (optional)",
                },
                "SPLUNK_SOURCE": {
                    "type": "string",
                    "description": "Source identifier (default: aishields:protect)",
                },
                "SPLUNK_SOURCETYPE": {
                    "type": "string",
                    "description": "Source type (default: _json)",
                },
            },
        }
