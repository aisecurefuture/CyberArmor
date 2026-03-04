"""
AIShields Protect - IBM QRadar Output

Sends normalized security events to IBM QRadar using two complementary
methods:

1. **Syslog LEEF** - Log Event Extended Format v2.0 events are forwarded
   over TCP/UDP to a QRadar log source. This is the primary ingestion
   path for real-time event correlation.

2. **REST API** - Used for pushing reference data (e.g. threat indicators)
   and for programmatic offense creation when the event severity warrants
   immediate attention.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from outputs.base import SIEMOutput

logger = logging.getLogger("siem-connector.outputs.qradar")

# ---------------------------------------------------------------------------
# LEEF severity mapping  (QRadar 0-10 scale)
# ---------------------------------------------------------------------------
_SEVERITY_TO_LEEF: dict[str, int] = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
}

# Syslog facility LOCAL4 = 20, severity mapping to syslog severity
_FACILITY = 20  # LOCAL4
_SYSLOG_SEV: dict[str, int] = {
    "critical": 2,   # Critical
    "high": 3,       # Error
    "medium": 4,     # Warning
    "low": 5,        # Notice
    "info": 6,       # Informational
}


class QRadarOutput(SIEMOutput):
    """IBM QRadar output adapter (LEEF syslog + REST API)."""

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _validate_config(self) -> None:
        self._require_config("QRADAR_HOST")
        # Either syslog or REST (or both) must be usable
        has_syslog = bool(self._config.get("QRADAR_SYSLOG_PORT"))
        has_rest = bool(self._config.get("QRADAR_API_TOKEN"))
        if not has_syslog and not has_rest:
            raise ValueError(
                "QRadar output requires at least QRADAR_SYSLOG_PORT "
                "(for LEEF syslog) or QRADAR_API_TOKEN (for REST API)."
            )

    @property
    def _host(self) -> str:
        return self._config["QRADAR_HOST"]

    @property
    def _syslog_port(self) -> int:
        return int(self._config.get("QRADAR_SYSLOG_PORT", 514))

    @property
    def _syslog_protocol(self) -> str:
        return self._config.get("QRADAR_SYSLOG_PROTOCOL", "tcp").lower()

    @property
    def _syslog_tls(self) -> bool:
        return self._config.get("QRADAR_SYSLOG_TLS", "false").lower() in (
            "true", "1", "yes",
        )

    @property
    def _api_url(self) -> str:
        base = self._config.get("QRADAR_API_URL")
        if base:
            return base.rstrip("/")
        scheme = "https"
        return f"{scheme}://{self._host}"

    @property
    def _api_token(self) -> Optional[str]:
        return self._config.get("QRADAR_API_TOKEN")

    @property
    def _api_headers(self) -> dict[str, str]:
        return {
            "SEC": self._api_token or "",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Version": self._config.get("QRADAR_API_VERSION", "19.0"),
        }

    @property
    def _auto_offense(self) -> bool:
        return self._config.get(
            "QRADAR_AUTO_OFFENSE", "false"
        ).lower() in ("true", "1", "yes")

    @property
    def _offense_severity_threshold(self) -> int:
        """Minimum numeric severity to auto-create an offense (default 8 = high)."""
        return int(self._config.get("QRADAR_OFFENSE_THRESHOLD", "8"))

    # ------------------------------------------------------------------
    # LEEF v2.0 formatting
    # ------------------------------------------------------------------

    def _build_leef(self, event: dict[str, Any]) -> str:
        """Build a LEEF 2.0 formatted string for QRadar ingestion.

        LEEF 2.0 format:
            LEEF:2.0|Vendor|Product|Version|EventID|<delimiter>|key=value<delimiter>key=value

        Uses tab as the default attribute delimiter.
        """
        delimiter = "\t"
        header = (
            f"LEEF:2.0|AIShields|Protect|"
            f"{event.get('product_version', '1.0.0')}|"
            f"{event.get('event_type', 'generic')}|{delimiter}|"
        )

        severity = event.get("severity", "info")
        attrs: dict[str, str] = {
            "devTime": event.get("timestamp", ""),
            "sev": str(_SEVERITY_TO_LEEF.get(severity, 1)),
            "cat": event.get("event_type", ""),
            "src": event.get("source_service", ""),
            "usrName": event.get("tenant_id", ""),
            "msg": event.get("title", ""),
            "reason": event.get("description", ""),
            "eventId": event.get("event_id", ""),
            "product": event.get("product", "AIShields Protect"),
            "schemaVersion": event.get("schema_version", "1.0"),
        }

        # Flatten details into LEEF attributes
        details = event.get("details") or {}
        for key, value in details.items():
            safe_val = json.dumps(value) if isinstance(value, (dict, list)) else str(value)
            # LEEF keys must not contain the delimiter character
            attrs[f"cs_{key}"] = safe_val.replace("\t", " ")

        tags = event.get("tags")
        if tags:
            attrs["tags"] = ",".join(tags)

        body = delimiter.join(f"{k}={v}" for k, v in attrs.items())
        return header + body

    def _build_syslog_message(self, event: dict[str, Any]) -> str:
        """Wrap a LEEF payload in an RFC 5424 syslog message."""
        severity = event.get("severity", "info")
        syslog_sev = _SYSLOG_SEV.get(severity, 6)
        priority = _FACILITY * 8 + syslog_sev

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        hostname = "aishields-protect"
        app_name = "siem-connector"
        proc_id = "-"
        msg_id = event.get("event_type", "-")

        leef_body = self._build_leef(event)

        # RFC 5424 header
        header = (
            f"<{priority}>1 {timestamp} {hostname} {app_name} "
            f"{proc_id} {msg_id} - "
        )
        return header + leef_body

    # ------------------------------------------------------------------
    # Syslog transport
    # ------------------------------------------------------------------

    async def _send_syslog(self, message: str) -> None:
        """Send a syslog message over the configured transport (TCP/UDP/TLS)."""
        encoded = message.encode("utf-8")

        if self._syslog_protocol == "udp":
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._send_udp, encoded)
        else:
            await self._send_tcp(encoded)

    def _send_udp(self, data: bytes) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(data, (self._host, self._syslog_port))
        finally:
            sock.close()

    async def _send_tcp(self, data: bytes) -> None:
        """Send data over TCP (optionally TLS-wrapped)."""
        ssl_context = None
        if self._syslog_tls:
            ssl_context = ssl.create_default_context()
            ca_cert = self._config.get("QRADAR_TLS_CA_CERT")
            if ca_cert:
                ssl_context.load_verify_locations(ca_cert)
            else:
                # Allow self-signed certs if no CA provided
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.open_connection(
            self._host, self._syslog_port, ssl=ssl_context
        )
        try:
            # Newline-framed for TCP syslog
            writer.write(data + b"\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    # ------------------------------------------------------------------
    # REST API helpers
    # ------------------------------------------------------------------

    async def _post_reference_data(
        self, event: dict[str, Any]
    ) -> None:
        """Push threat-relevant fields to a QRadar reference set.

        This enriches QRadar correlation rules with IOCs from AIShields.
        """
        if not self._api_token:
            return

        ref_set_name = self._config.get(
            "QRADAR_REFERENCE_SET", "AIShields_Events"
        )
        url = (
            f"{self._api_url}/api/reference_data/sets/{ref_set_name}"
            f"?value={event.get('event_id', '')}"
        )

        try:
            async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
                resp = await client.post(url, headers=self._api_headers)
                if resp.status_code not in (200, 201):
                    logger.warning(
                        "QRadar reference set update returned %d: %s",
                        resp.status_code,
                        resp.text,
                    )
        except Exception as exc:
            logger.warning("Failed to update QRadar reference set: %s", exc)

    async def _create_offense_note(
        self, event: dict[str, Any]
    ) -> None:
        """Create a custom offense via the QRadar REST API for high-severity events.

        QRadar does not expose a direct 'create offense' REST endpoint;
        instead we post a syslog-triggered custom rule. As a lightweight
        alternative, we post a note to an existing offense or log it via
        the custom actions endpoint.
        """
        if not self._api_token or not self._auto_offense:
            return

        sev_num = event.get("severity_numeric", 0)
        if sev_num < self._offense_severity_threshold:
            return

        # Use the custom actions / SIEM event forwarding approach
        url = f"{self._api_url}/api/siem/offenses"
        params = {
            "filter": "status=OPEN",
            "fields": "id",
            "Range": "items=0-0",
        }

        try:
            async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
                resp = await client.get(
                    url, headers=self._api_headers, params=params
                )
                if resp.status_code == 200:
                    offenses = resp.json()
                    if offenses:
                        offense_id = offenses[0]["id"]
                        note_url = (
                            f"{self._api_url}/api/siem/offenses/"
                            f"{offense_id}/notes"
                        )
                        note_text = (
                            f"[AIShields Protect] {event.get('severity', '').upper()}: "
                            f"{event.get('title', '')} - {event.get('description', '')}"
                        )
                        await client.post(
                            note_url,
                            headers=self._api_headers,
                            params={"note_text": note_text},
                        )
                        logger.info(
                            "Posted offense note to QRadar offense %d",
                            offense_id,
                        )
        except Exception as exc:
            logger.warning("Failed to create QRadar offense note: %s", exc)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def send_event(self, event: dict[str, Any]) -> None:
        """Send event via syslog LEEF and optionally via REST API."""
        if self._config.get("QRADAR_SYSLOG_PORT"):
            msg = self._build_syslog_message(event)
            await self._send_syslog(msg)
            logger.debug(
                "LEEF event sent to QRadar %s:%d",
                self._host,
                self._syslog_port,
            )

        # Push reference data and check offense threshold
        if self._api_token:
            await self._post_reference_data(event)
            await self._create_offense_note(event)

    async def send_batch(self, events: list[dict[str, Any]]) -> None:
        """Send a batch of events.

        Syslog events are sent individually (LEEF has no batch mode).
        REST API reference-set updates are batched where possible.
        """
        for event in events:
            await self.send_event(event)
        logger.info(
            "Batch of %d LEEF events sent to QRadar %s",
            len(events),
            self._host,
        )

    async def test_connection(self) -> bool:
        """Test connectivity to QRadar via syslog and/or REST API."""
        syslog_ok = True
        rest_ok = True

        # Test syslog
        if self._config.get("QRADAR_SYSLOG_PORT"):
            try:
                test_msg = (
                    f"<{_FACILITY * 8 + 6}>1 "
                    f"{datetime.now(timezone.utc).isoformat()} "
                    f"aishields-protect siem-connector - test - "
                    f"LEEF:2.0|AIShields|Protect|1.0.0|connectivity-test|"
                )
                await self._send_syslog(test_msg)
            except Exception as exc:
                logger.warning("QRadar syslog connectivity test failed: %s", exc)
                syslog_ok = False

        # Test REST API
        if self._api_token:
            try:
                url = f"{self._api_url}/api/system/about"
                async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                    resp = await client.get(url, headers=self._api_headers)
                    rest_ok = resp.status_code == 200
            except Exception as exc:
                logger.warning("QRadar REST API connectivity test failed: %s", exc)
                rest_ok = False

        return syslog_ok and rest_ok

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    @classmethod
    def get_config_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "required": ["QRADAR_HOST"],
            "properties": {
                "QRADAR_HOST": {
                    "type": "string",
                    "description": "QRadar console hostname or IP address.",
                },
                "QRADAR_SYSLOG_PORT": {
                    "type": "integer",
                    "description": "Syslog listener port (default: 514).",
                },
                "QRADAR_SYSLOG_PROTOCOL": {
                    "type": "string",
                    "enum": ["tcp", "udp"],
                    "description": "Syslog transport protocol (default: tcp).",
                },
                "QRADAR_SYSLOG_TLS": {
                    "type": "string",
                    "description": "Enable TLS for syslog transport (default: false).",
                },
                "QRADAR_TLS_CA_CERT": {
                    "type": "string",
                    "description": "Path to CA certificate for TLS verification.",
                },
                "QRADAR_API_TOKEN": {
                    "type": "string",
                    "description": "QRadar authorized service token for REST API.",
                },
                "QRADAR_API_URL": {
                    "type": "string",
                    "description": "Override full QRadar API base URL.",
                },
                "QRADAR_API_VERSION": {
                    "type": "string",
                    "description": "QRadar API version header (default: 19.0).",
                },
                "QRADAR_REFERENCE_SET": {
                    "type": "string",
                    "description": (
                        "Reference set name for event enrichment "
                        "(default: AIShields_Events)."
                    ),
                },
                "QRADAR_AUTO_OFFENSE": {
                    "type": "string",
                    "description": (
                        "Auto-create offense notes for high-severity events "
                        "(default: false)."
                    ),
                },
                "QRADAR_OFFENSE_THRESHOLD": {
                    "type": "integer",
                    "description": (
                        "Minimum severity_numeric to trigger offense notes "
                        "(default: 8)."
                    ),
                },
            },
        }
