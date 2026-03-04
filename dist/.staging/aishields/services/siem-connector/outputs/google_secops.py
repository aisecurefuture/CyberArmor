"""
AIShields Protect - Google SecOps (Chronicle) Output

Sends normalized security events to Google Security Operations (formerly
Chronicle) via the Chronicle Ingestion API v2.  Supports:

- Chronicle Ingestion API v2 for UDM event creation
- Unified Data Model (UDM) event format mapping
- MALACHITE ingestion feeds for batch log ingestion
- Google Cloud service account authentication (OAuth2)
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from outputs.base import SIEMOutput

logger = logging.getLogger("siem-connector.outputs.google_secops")

# ---------------------------------------------------------------------------
# UDM severity mapping
# ---------------------------------------------------------------------------
_SEVERITY_TO_UDM: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFORMATIONAL",
}

# UDM event type mapping
_EVENT_TYPE_MAP: dict[str, str] = {
    "generic": "GENERIC_EVENT",
    "detection": "SCAN_UNCATEGORIZED",
    "policy_violation": "SCAN_VULN_HOST",
    "authentication": "USER_LOGIN",
    "authorization": "USER_RESOURCE_ACCESS",
    "data_exfiltration": "SCAN_NETWORK",
    "injection": "SCAN_VULN_HOST",
    "prompt_injection": "SCAN_VULN_HOST",
    "model_abuse": "SCAN_UNCATEGORIZED",
    "anomaly": "STATUS_UNCATEGORIZED",
    "test": "GENERIC_EVENT",
}


class GoogleSecOpsOutput(SIEMOutput):
    """Google SecOps (Chronicle) output via Ingestion API v2."""

    _access_token: Optional[str] = None
    _token_expiry: float = 0.0

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _validate_config(self) -> None:
        self._require_config("CHRONICLE_CUSTOMER_ID")
        # Need either a service account key file or explicit credentials
        has_sa_file = bool(self._config.get("CHRONICLE_SA_KEY_FILE"))
        has_sa_json = bool(self._config.get("CHRONICLE_SA_KEY_JSON"))
        has_token = bool(self._config.get("CHRONICLE_API_KEY"))
        if not has_sa_file and not has_sa_json and not has_token:
            raise ValueError(
                "GoogleSecOpsOutput requires CHRONICLE_SA_KEY_FILE, "
                "CHRONICLE_SA_KEY_JSON, or CHRONICLE_API_KEY."
            )

    @property
    def _customer_id(self) -> str:
        return self._config["CHRONICLE_CUSTOMER_ID"]

    @property
    def _region(self) -> str:
        return self._config.get("CHRONICLE_REGION", "us")

    @property
    def _base_url(self) -> str:
        override = self._config.get("CHRONICLE_API_URL")
        if override:
            return override.rstrip("/")
        region = self._region
        if region == "us":
            return "https://malachiteingestion-pa.googleapis.com"
        elif region == "europe":
            return "https://europe-malachiteingestion-pa.googleapis.com"
        elif region == "asia":
            return "https://asia-southeast1-malachiteingestion-pa.googleapis.com"
        return f"https://{region}-malachiteingestion-pa.googleapis.com"

    @property
    def _log_type(self) -> str:
        return self._config.get("CHRONICLE_LOG_TYPE", "AISHIELDS_PROTECT")

    @property
    def _feed_source_type(self) -> str:
        """MALACHITE feed source type for batch ingestion."""
        return self._config.get("CHRONICLE_FEED_SOURCE_TYPE", "API")

    # ------------------------------------------------------------------
    # OAuth2 service account authentication
    # ------------------------------------------------------------------

    async def _get_access_token(self) -> str:
        """Obtain an OAuth2 access token using a Google service account.

        Supports both a JSON key file path and inline JSON key content.
        Falls back to CHRONICLE_API_KEY for simple API key auth.
        """
        # API key auth (simplest)
        api_key = self._config.get("CHRONICLE_API_KEY")
        if api_key:
            return api_key

        # Check cached token
        if self._access_token and time.time() < self._token_expiry - 60:
            return self._access_token

        # Load service account credentials
        sa_key: dict[str, Any]
        sa_file = self._config.get("CHRONICLE_SA_KEY_FILE")
        sa_json = self._config.get("CHRONICLE_SA_KEY_JSON")
        if sa_file:
            with open(sa_file, "r") as f:
                sa_key = json.load(f)
        elif sa_json:
            sa_key = json.loads(sa_json)
        else:
            raise ValueError("No service account credentials available.")

        # Build JWT for token exchange
        import base64
        import hashlib
        import hmac

        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": sa_key["client_email"],
            "scope": "https://www.googleapis.com/auth/malachite-ingestion",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600,
        }

        def _b64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

        header_b64 = _b64url(json.dumps(header).encode())
        claims_b64 = _b64url(json.dumps(claims).encode())
        signing_input = f"{header_b64}.{claims_b64}"

        # RSA-SHA256 signature using the service account private key
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            private_key = serialization.load_pem_private_key(
                sa_key["private_key"].encode(), password=None
            )
            signature = private_key.sign(
                signing_input.encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except ImportError:
            logger.error(
                "cryptography package required for service account auth. "
                "Install with: pip install cryptography"
            )
            raise

        jwt_token = f"{signing_input}.{_b64url(signature)}"

        # Exchange JWT for access token
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": jwt_token,
                },
            )
            if resp.status_code != 200:
                raise ConnectionError(
                    f"Google OAuth2 token exchange failed: {resp.status_code} {resp.text}"
                )
            token_data = resp.json()
            self._access_token = token_data["access_token"]
            self._token_expiry = time.time() + token_data.get("expires_in", 3600)
            return self._access_token

    async def _get_auth_headers(self) -> dict[str, str]:
        """Build authorization headers."""
        token = await self._get_access_token()
        # API key auth uses a query parameter, but we include it as a header
        # for consistency. The actual API routing is handled in the URL.
        api_key = self._config.get("CHRONICLE_API_KEY")
        if api_key:
            return {
                "Content-Type": "application/json",
                "X-goog-api-key": api_key,
            }
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }

    # ------------------------------------------------------------------
    # UDM event mapping
    # ------------------------------------------------------------------

    def _map_to_udm(self, event: dict[str, Any]) -> dict[str, Any]:
        """Map a normalized AIShields event to Chronicle UDM format.

        Returns a UDM event dictionary conforming to the Chronicle
        Ingestion API v2 UDM schema.
        """
        severity = event.get("severity", "info")
        event_type = event.get("event_type", "generic")

        udm_event: dict[str, Any] = {
            "metadata": {
                "event_timestamp": event.get(
                    "timestamp", datetime.now(timezone.utc).isoformat()
                ),
                "event_type": _EVENT_TYPE_MAP.get(event_type, "GENERIC_EVENT"),
                "vendor_name": "AIShields",
                "product_name": "Protect",
                "product_version": event.get("product_version", "1.0.0"),
                "description": event.get("description", ""),
                "product_event_type": event_type,
                "log_type": self._log_type,
                "ingested_timestamp": event.get(
                    "ingested_at", datetime.now(timezone.utc).isoformat()
                ),
            },
            "additional": {
                "fields": {
                    "event_id": {"string_value": event.get("event_id", "")},
                    "tenant_id": {"string_value": event.get("tenant_id", "")},
                    "source_service": {
                        "string_value": event.get("source_service", "")
                    },
                    "schema_version": {
                        "string_value": event.get("schema_version", "1.0")
                    },
                },
            },
            "security_result": [
                {
                    "severity": _SEVERITY_TO_UDM.get(severity, "INFORMATIONAL"),
                    "summary": event.get("title", ""),
                    "description": event.get("description", ""),
                    "category": event_type.upper(),
                    "rule_name": event.get("title", ""),
                    "alert_state": (
                        "ALERTING"
                        if severity in ("critical", "high")
                        else "NOT_ALERTING"
                    ),
                },
            ],
        }

        # Add details as additional fields
        details = event.get("details") or {}
        for key, value in details.items():
            if isinstance(value, bool):
                udm_event["additional"]["fields"][f"detail_{key}"] = {
                    "bool_value": value
                }
            elif isinstance(value, (int, float)):
                udm_event["additional"]["fields"][f"detail_{key}"] = {
                    "number_value": value
                }
            else:
                udm_event["additional"]["fields"][f"detail_{key}"] = {
                    "string_value": json.dumps(value)
                    if isinstance(value, (dict, list))
                    else str(value)
                }

        # Tags
        tags = event.get("tags", [])
        if tags:
            udm_event["additional"]["fields"]["tags"] = {
                "string_value": ",".join(tags)
            }

        return udm_event

    # ------------------------------------------------------------------
    # Sending via Ingestion API v2
    # ------------------------------------------------------------------

    async def send_event(self, event: dict[str, Any]) -> None:
        """Send a single event via the Chronicle Ingestion API v2."""
        await self.send_batch([event])

    async def send_batch(self, events: list[dict[str, Any]]) -> None:
        """Send events using the Chronicle Ingestion API v2 (UDM events).

        Uses the CreateUDMEvents endpoint for structured UDM event
        ingestion, which provides better parsing and field extraction
        than raw log ingestion.
        """
        headers = await self._get_auth_headers()
        udm_events = [self._map_to_udm(e) for e in events]

        # UDM event creation endpoint
        url = (
            f"{self._base_url}/v2/udmevents:batchCreate"
        )

        payload = {
            "customer_id": self._customer_id,
            "events": [
                {"udm": udm_event} for udm_event in udm_events
            ],
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                url,
                headers=headers,
                content=json.dumps(payload),
            )
            if resp.status_code not in (200, 202):
                logger.error(
                    "Chronicle Ingestion API returned %d: %s",
                    resp.status_code,
                    resp.text,
                )
                raise ConnectionError(
                    f"Chronicle Ingestion API error {resp.status_code}: {resp.text}"
                )
            logger.info(
                "Sent %d UDM events to Chronicle (customer: %s)",
                len(events),
                self._customer_id,
            )

    async def send_malachite_feed(
        self, events: list[dict[str, Any]]
    ) -> None:
        """Alternative ingestion path using MALACHITE feed (raw log lines).

        This is useful for high-volume ingestion where UDM mapping
        can be deferred to Chronicle parsers.
        """
        headers = await self._get_auth_headers()
        url = f"{self._base_url}/v2/unstructuredlogentries:batchCreate"

        log_entries = []
        for event in events:
            log_entries.append({
                "log_text": json.dumps(event),
                "ts_epoch_microseconds": int(time.time() * 1_000_000),
            })

        payload = {
            "customer_id": self._customer_id,
            "log_type": self._log_type,
            "entries": log_entries,
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                url,
                headers=headers,
                content=json.dumps(payload),
            )
            if resp.status_code not in (200, 202):
                logger.error(
                    "Chronicle MALACHITE feed returned %d: %s",
                    resp.status_code,
                    resp.text,
                )
                raise ConnectionError(
                    f"Chronicle MALACHITE error {resp.status_code}: {resp.text}"
                )
            logger.info(
                "Sent %d log entries via MALACHITE feed to Chronicle",
                len(events),
            )

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    async def test_connection(self) -> bool:
        """Verify connectivity by sending a test UDM event."""
        try:
            headers = await self._get_auth_headers()
            # Use a lightweight endpoint to verify auth
            url = f"{self._base_url}/v2/udmevents:batchCreate"
            test_event = {
                "metadata": {
                    "event_timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "GENERIC_EVENT",
                    "vendor_name": "AIShields",
                    "product_name": "Protect",
                    "description": "Connectivity test",
                    "product_event_type": "test",
                },
            }
            payload = {
                "customer_id": self._customer_id,
                "events": [{"udm": test_event}],
            }

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    url,
                    headers=headers,
                    content=json.dumps(payload),
                )
                return resp.status_code in (200, 202)
        except Exception as exc:
            logger.warning("Chronicle connectivity test failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    @classmethod
    def get_config_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "required": ["CHRONICLE_CUSTOMER_ID"],
            "properties": {
                "CHRONICLE_CUSTOMER_ID": {
                    "type": "string",
                    "description": "Chronicle customer/instance ID (GUID).",
                },
                "CHRONICLE_SA_KEY_FILE": {
                    "type": "string",
                    "description": (
                        "Path to Google service account JSON key file."
                    ),
                },
                "CHRONICLE_SA_KEY_JSON": {
                    "type": "string",
                    "description": (
                        "Inline Google service account JSON key content."
                    ),
                },
                "CHRONICLE_API_KEY": {
                    "type": "string",
                    "description": "Google API key (alternative to SA auth).",
                },
                "CHRONICLE_REGION": {
                    "type": "string",
                    "enum": ["us", "europe", "asia"],
                    "description": "Chronicle data region (default: us).",
                },
                "CHRONICLE_API_URL": {
                    "type": "string",
                    "description": "Override the Chronicle Ingestion API URL.",
                },
                "CHRONICLE_LOG_TYPE": {
                    "type": "string",
                    "description": (
                        "Chronicle log type identifier "
                        "(default: AISHIELDS_PROTECT)."
                    ),
                },
                "CHRONICLE_FEED_SOURCE_TYPE": {
                    "type": "string",
                    "description": (
                        "MALACHITE feed source type (default: API)."
                    ),
                },
            },
        }
