"""
CyberArmor.ai Protect - Generic Syslog / CEF Output

Sends normalized security events over RFC 5424 syslog using ArcSight
Common Event Format (CEF).  Supports:

- CEF format v0 for broad SIEM compatibility (ArcSight, LogRhythm, etc.)
- RFC 5424 syslog framing
- TCP, UDP, and TLS transport
- Configurable syslog facility and severity mapping
- Octet-counting framing for TCP (RFC 6587)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Optional

from outputs.base import SIEMOutput

logger = logging.getLogger("siem-connector.outputs.syslog_cef")

# ---------------------------------------------------------------------------
# Syslog facility codes (RFC 5424)
# ---------------------------------------------------------------------------
FACILITY_MAP: dict[str, int] = {
    "kern": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "authpriv": 10,
    "ftp": 11,
    "ntp": 12,
    "audit": 13,
    "alert": 14,
    "clock": 15,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}

# ---------------------------------------------------------------------------
# CEF severity mapping (0-10 scale)
# ---------------------------------------------------------------------------
_CEF_SEVERITY: dict[str, int] = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
}

# Syslog severity from CyberArmor.ai severity
_SYSLOG_SEVERITY: dict[str, int] = {
    "critical": 2,   # Critical
    "high": 3,       # Error
    "medium": 4,     # Warning
    "low": 5,        # Notice
    "info": 6,       # Informational
}


def _escape_cef_value(value: str) -> str:
    """Escape special characters in a CEF extension value.

    CEF requires escaping backslashes, equals signs, and newlines
    in extension values.
    """
    value = value.replace("\\", "\\\\")
    value = value.replace("=", "\\=")
    value = value.replace("\n", "\\n")
    value = value.replace("\r", "\\r")
    return value


def _escape_cef_header(value: str) -> str:
    """Escape pipe characters in CEF header fields."""
    value = value.replace("\\", "\\\\")
    value = value.replace("|", "\\|")
    return value


class SyslogCEFOutput(SIEMOutput):
    """Generic Syslog / CEF output adapter supporting TCP/UDP/TLS."""

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _validate_config(self) -> None:
        self._require_config("SYSLOG_HOST")

    @property
    def _host(self) -> str:
        return self._config["SYSLOG_HOST"]

    @property
    def _port(self) -> int:
        return int(self._config.get("SYSLOG_PORT", 514))

    @property
    def _protocol(self) -> str:
        return self._config.get("SYSLOG_PROTOCOL", "tcp").lower()

    @property
    def _tls_enabled(self) -> bool:
        return self._config.get("SYSLOG_TLS", "false").lower() in (
            "true", "1", "yes",
        )

    @property
    def _tls_ca_cert(self) -> Optional[str]:
        return self._config.get("SYSLOG_TLS_CA_CERT")

    @property
    def _tls_client_cert(self) -> Optional[str]:
        return self._config.get("SYSLOG_TLS_CLIENT_CERT")

    @property
    def _tls_client_key(self) -> Optional[str]:
        return self._config.get("SYSLOG_TLS_CLIENT_KEY")

    @property
    def _facility(self) -> int:
        facility_name = self._config.get("SYSLOG_FACILITY", "local4").lower()
        return FACILITY_MAP.get(facility_name, 20)

    @property
    def _use_octet_counting(self) -> bool:
        """Use octet-counting framing for TCP (RFC 6587)."""
        return self._config.get(
            "SYSLOG_OCTET_COUNTING", "false"
        ).lower() in ("true", "1", "yes")

    @property
    def _max_message_size(self) -> int:
        """Maximum message size in bytes (default 65535 for TCP, 1024 for UDP)."""
        default = 1024 if self._protocol == "udp" else 65535
        return int(self._config.get("SYSLOG_MAX_SIZE", str(default)))

    # ------------------------------------------------------------------
    # CEF formatting
    # ------------------------------------------------------------------

    def _build_cef(self, event: dict[str, Any]) -> str:
        """Build a CEF v0 formatted string from a normalized event.

        CEF format:
            CEF:0|Device Vendor|Device Product|Device Version|
            Signature ID|Name|Severity|Extension

        Extension is a space-separated list of key=value pairs.
        """
        severity = event.get("severity", "info")
        cef_sev = _CEF_SEVERITY.get(severity, 1)

        # CEF header fields
        vendor = _escape_cef_header("CyberArmor.ai")
        product = _escape_cef_header("Protect")
        version = _escape_cef_header(event.get("product_version", "1.0.0"))
        sig_id = _escape_cef_header(event.get("event_type", "generic"))
        name = _escape_cef_header(event.get("title", "CyberArmor.ai Event"))

        header = f"CEF:0|{vendor}|{product}|{version}|{sig_id}|{name}|{cef_sev}|"

        # CEF extension key-value pairs
        extensions: dict[str, str] = {}

        # Timestamps
        ts = event.get("timestamp", "")
        if ts:
            # CEF rt (receipt time) expects epoch millis
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                extensions["rt"] = str(int(dt.timestamp() * 1000))
            except (ValueError, AttributeError):
                extensions["rt"] = ts

        extensions["deviceExternalId"] = event.get("event_id", "")
        extensions["cs1"] = event.get("tenant_id", "")
        extensions["cs1Label"] = "TenantId"
        extensions["cs2"] = event.get("source_service", "")
        extensions["cs2Label"] = "SourceService"
        extensions["msg"] = event.get("description", "")
        extensions["cat"] = event.get("event_type", "")
        extensions["cn1"] = str(event.get("severity_numeric", 0))
        extensions["cn1Label"] = "SeverityNumeric"

        # Schema metadata
        extensions["cs3"] = event.get("schema_version", "1.0")
        extensions["cs3Label"] = "SchemaVersion"

        # Tags
        tags = event.get("tags", [])
        if tags:
            extensions["cs4"] = ",".join(tags)
            extensions["cs4Label"] = "Tags"

        # Flatten details into custom string fields
        details = event.get("details") or {}
        detail_idx = 5  # cs5, cs6 for additional custom fields
        for key, value in details.items():
            if detail_idx > 6:
                # CEF has limited custom string fields; pack remaining into flexString
                break
            safe_val = (
                json.dumps(value)
                if isinstance(value, (dict, list))
                else str(value)
            )
            extensions[f"cs{detail_idx}"] = safe_val
            extensions[f"cs{detail_idx}Label"] = key
            detail_idx += 1

        # Remaining details go into a single JSON flex field
        if detail_idx <= len(details) + 4:
            remaining = {
                k: v
                for i, (k, v) in enumerate(details.items())
                if i >= detail_idx - 5
            }
            if remaining:
                extensions["flexString1"] = json.dumps(remaining)
                extensions["flexString1Label"] = "AdditionalDetails"

        # Build extension string
        ext_parts = []
        for k, v in extensions.items():
            ext_parts.append(f"{k}={_escape_cef_value(str(v))}")
        extension = " ".join(ext_parts)

        return header + extension

    def _build_syslog_message(self, event: dict[str, Any]) -> str:
        """Wrap a CEF payload in an RFC 5424 syslog message.

        Format:
            <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
        """
        severity = event.get("severity", "info")
        syslog_sev = _SYSLOG_SEVERITY.get(severity, 6)
        priority = self._facility * 8 + syslog_sev

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        hostname = self._config.get("SYSLOG_HOSTNAME", "aishields-protect")
        app_name = self._config.get("SYSLOG_APP_NAME", "siem-connector")
        proc_id = "-"
        msg_id = event.get("event_type", "-")

        cef_body = self._build_cef(event)

        # RFC 5424: structured data (nil for now)
        structured_data = "-"

        message = (
            f"<{priority}>1 {timestamp} {hostname} {app_name} "
            f"{proc_id} {msg_id} {structured_data} {cef_body}"
        )

        # Truncate if necessary
        if len(message.encode("utf-8")) > self._max_message_size:
            max_len = self._max_message_size
            message = message[: max_len - 3] + "..."

        return message

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Build an SSL context for TLS transport."""
        ctx = ssl.create_default_context()
        ca_cert = self._tls_ca_cert
        if ca_cert:
            ctx.load_verify_locations(ca_cert)
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        client_cert = self._tls_client_cert
        client_key = self._tls_client_key
        if client_cert:
            ctx.load_cert_chain(client_cert, keyfile=client_key)

        return ctx

    async def _send_message(self, message: str) -> None:
        """Send a syslog message over the configured transport."""
        encoded = message.encode("utf-8")

        if self._protocol == "udp":
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._send_udp, encoded)
        else:
            await self._send_tcp(encoded)

    def _send_udp(self, data: bytes) -> None:
        """Send data over UDP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(data, (self._host, self._port))
        finally:
            sock.close()

    async def _send_tcp(self, data: bytes) -> None:
        """Send data over TCP, optionally TLS-wrapped."""
        ssl_context = self._build_ssl_context() if self._tls_enabled else None

        reader, writer = await asyncio.open_connection(
            self._host, self._port, ssl=ssl_context
        )
        try:
            if self._use_octet_counting:
                # RFC 6587 octet-counting: prefix message with byte length
                framed = f"{len(data)} ".encode("ascii") + data
                writer.write(framed)
            else:
                # Newline-delimited framing (most common for TCP syslog)
                writer.write(data + b"\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def send_event(self, event: dict[str, Any]) -> None:
        """Format and send a single event as a CEF syslog message."""
        message = self._build_syslog_message(event)
        await self._send_message(message)
        logger.debug(
            "CEF event sent to %s:%d (%s)",
            self._host,
            self._port,
            self._protocol.upper(),
        )

    async def send_batch(self, events: list[dict[str, Any]]) -> None:
        """Send a batch of events as individual syslog messages.

        Syslog is inherently single-message; we send each event
        individually but reuse the TCP connection where possible.
        """
        if self._protocol == "udp":
            for event in events:
                await self.send_event(event)
        else:
            # Reuse a single TCP connection for the batch
            ssl_context = self._build_ssl_context() if self._tls_enabled else None
            reader, writer = await asyncio.open_connection(
                self._host, self._port, ssl=ssl_context
            )
            try:
                for event in events:
                    message = self._build_syslog_message(event)
                    data = message.encode("utf-8")
                    if self._use_octet_counting:
                        framed = f"{len(data)} ".encode("ascii") + data
                        writer.write(framed)
                    else:
                        writer.write(data + b"\n")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        logger.info(
            "Batch of %d CEF events sent to %s:%d (%s)",
            len(events),
            self._host,
            self._port,
            self._protocol.upper(),
        )

    async def test_connection(self) -> bool:
        """Test connectivity by sending a minimal syslog message."""
        try:
            test_cef = (
                "CEF:0|CyberArmor.ai|Protect|1.0.0|test|"
                "Connectivity Test|1|msg=CyberArmor.ai syslog connectivity test"
            )
            priority = self._facility * 8 + 6  # Informational
            timestamp = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            )
            hostname = self._config.get("SYSLOG_HOSTNAME", "aishields-protect")
            message = (
                f"<{priority}>1 {timestamp} {hostname} siem-connector "
                f"- test - {test_cef}"
            )
            await self._send_message(message)
            return True
        except Exception as exc:
            logger.warning(
                "Syslog connectivity test failed (%s:%d %s): %s",
                self._host,
                self._port,
                self._protocol.upper(),
                exc,
            )
            return False

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    @classmethod
    def get_config_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "required": ["SYSLOG_HOST"],
            "properties": {
                "SYSLOG_HOST": {
                    "type": "string",
                    "description": "Syslog server hostname or IP address.",
                },
                "SYSLOG_PORT": {
                    "type": "integer",
                    "description": "Syslog server port (default: 514).",
                },
                "SYSLOG_PROTOCOL": {
                    "type": "string",
                    "enum": ["tcp", "udp"],
                    "description": "Transport protocol (default: tcp).",
                },
                "SYSLOG_TLS": {
                    "type": "string",
                    "description": (
                        "Enable TLS for TCP transport (default: false)."
                    ),
                },
                "SYSLOG_TLS_CA_CERT": {
                    "type": "string",
                    "description": "Path to CA certificate for TLS verification.",
                },
                "SYSLOG_TLS_CLIENT_CERT": {
                    "type": "string",
                    "description": "Path to client certificate for mutual TLS.",
                },
                "SYSLOG_TLS_CLIENT_KEY": {
                    "type": "string",
                    "description": "Path to client key for mutual TLS.",
                },
                "SYSLOG_FACILITY": {
                    "type": "string",
                    "description": (
                        "Syslog facility name (default: local4). "
                        "Options: kern, user, mail, daemon, auth, syslog, "
                        "local0-local7, etc."
                    ),
                },
                "SYSLOG_HOSTNAME": {
                    "type": "string",
                    "description": (
                        "Hostname to include in syslog header "
                        "(default: aishields-protect)."
                    ),
                },
                "SYSLOG_APP_NAME": {
                    "type": "string",
                    "description": (
                        "Application name in syslog header "
                        "(default: siem-connector)."
                    ),
                },
                "SYSLOG_OCTET_COUNTING": {
                    "type": "string",
                    "description": (
                        "Use RFC 6587 octet-counting framing for TCP "
                        "(default: false)."
                    ),
                },
                "SYSLOG_MAX_SIZE": {
                    "type": "integer",
                    "description": (
                        "Maximum message size in bytes "
                        "(default: 1024 for UDP, 65535 for TCP)."
                    ),
                },
            },
        }
