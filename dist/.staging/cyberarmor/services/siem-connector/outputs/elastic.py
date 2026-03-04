"""
CyberArmor.ai Protect - Elastic SIEM Output

Sends normalized security events to Elasticsearch using the Bulk API
with Elastic Common Schema (ECS) field mapping.  Supports:

- Elasticsearch Bulk API for high-throughput ingestion
- ECS field mapping for native Elastic SIEM rule compatibility
- Index Lifecycle Management (ILM) policy bootstrapping
- API key, basic auth, and cloud ID authentication
- Automatic index template creation on first connect
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from outputs.base import SIEMOutput

logger = logging.getLogger("siem-connector.outputs.elastic")

# ---------------------------------------------------------------------------
# ECS severity mapping
# ---------------------------------------------------------------------------
_SEVERITY_TO_ECS: dict[str, dict[str, Any]] = {
    "critical": {"event.severity": 1, "event.risk_score": 95.0},
    "high": {"event.severity": 2, "event.risk_score": 75.0},
    "medium": {"event.severity": 3, "event.risk_score": 50.0},
    "low": {"event.severity": 4, "event.risk_score": 25.0},
    "info": {"event.severity": 5, "event.risk_score": 5.0},
}

# Default ILM policy
_DEFAULT_ILM_POLICY = {
    "policy": {
        "phases": {
            "hot": {
                "min_age": "0ms",
                "actions": {
                    "rollover": {
                        "max_primary_shard_size": "50gb",
                        "max_age": "7d",
                    },
                    "set_priority": {"priority": 100},
                },
            },
            "warm": {
                "min_age": "30d",
                "actions": {
                    "shrink": {"number_of_shards": 1},
                    "forcemerge": {"max_num_segments": 1},
                    "set_priority": {"priority": 50},
                },
            },
            "cold": {
                "min_age": "90d",
                "actions": {
                    "set_priority": {"priority": 0},
                },
            },
            "delete": {
                "min_age": "365d",
                "actions": {"delete": {}},
            },
        },
    },
}

# Index template mapping for CyberArmor.ai events using ECS
_INDEX_TEMPLATE = {
    "index_patterns": ["aishields-protect-*"],
    "template": {
        "settings": {
            "index.lifecycle.name": "aishields-protect-ilm",
            "index.lifecycle.rollover_alias": "aishields-protect",
            "number_of_shards": 1,
            "number_of_replicas": 1,
        },
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "kind": {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "severity": {"type": "integer"},
                        "risk_score": {"type": "float"},
                        "created": {"type": "date"},
                        "ingested": {"type": "date"},
                        "module": {"type": "keyword"},
                        "dataset": {"type": "keyword"},
                        "provider": {"type": "keyword"},
                    },
                },
                "message": {"type": "text"},
                "labels": {"type": "object", "dynamic": True},
                "tags": {"type": "keyword"},
                "observer": {
                    "properties": {
                        "product": {"type": "keyword"},
                        "vendor": {"type": "keyword"},
                        "version": {"type": "keyword"},
                    },
                },
                "organization": {
                    "properties": {
                        "id": {"type": "keyword"},
                    },
                },
                "rule": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "description": {"type": "text"},
                        "category": {"type": "keyword"},
                    },
                },
                "aishields": {
                    "properties": {
                        "source_service": {"type": "keyword"},
                        "event_type": {"type": "keyword"},
                        "schema_version": {"type": "keyword"},
                        "details": {"type": "object", "dynamic": True},
                    },
                },
            },
        },
    },
    "priority": 200,
    "composed_of": [],
    "_meta": {
        "description": "CyberArmor.ai Protect security events (ECS-compatible)",
    },
}


class ElasticOutput(SIEMOutput):
    """Elastic SIEM output via Elasticsearch Bulk API with ECS mapping."""

    _template_bootstrapped: bool = False

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _validate_config(self) -> None:
        # Need either ELASTIC_URL or ELASTIC_CLOUD_ID
        has_url = bool(self._config.get("ELASTIC_URL"))
        has_cloud = bool(self._config.get("ELASTIC_CLOUD_ID"))
        if not has_url and not has_cloud:
            raise ValueError(
                "ElasticOutput requires ELASTIC_URL or ELASTIC_CLOUD_ID."
            )
        # Need some form of auth
        has_api_key = bool(self._config.get("ELASTIC_API_KEY"))
        has_basic = bool(
            self._config.get("ELASTIC_USERNAME")
            and self._config.get("ELASTIC_PASSWORD")
        )
        if not has_api_key and not has_basic:
            raise ValueError(
                "ElasticOutput requires ELASTIC_API_KEY or "
                "ELASTIC_USERNAME + ELASTIC_PASSWORD."
            )

    @property
    def _base_url(self) -> str:
        url = self._config.get("ELASTIC_URL")
        if url:
            return url.rstrip("/")
        # Derive from cloud ID (base64 encoded: cluster_name:es_endpoint:kibana_endpoint)
        import base64

        cloud_id = self._config["ELASTIC_CLOUD_ID"]
        parts = cloud_id.split(":")
        if len(parts) >= 2:
            decoded = base64.b64decode(parts[1]).decode("utf-8")
            host_parts = decoded.split("$")
            if len(host_parts) >= 2:
                base_domain = host_parts[0]
                es_id = host_parts[1]
                return f"https://{es_id}.{base_domain}"
        raise ValueError(f"Cannot parse ELASTIC_CLOUD_ID: {cloud_id}")

    @property
    def _index_prefix(self) -> str:
        return self._config.get("ELASTIC_INDEX_PREFIX", "aishields-protect")

    @property
    def _pipeline(self) -> Optional[str]:
        return self._config.get("ELASTIC_PIPELINE")

    @property
    def _auth_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/x-ndjson"}
        api_key = self._config.get("ELASTIC_API_KEY")
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"
        else:
            import base64

            creds = (
                f"{self._config['ELASTIC_USERNAME']}:"
                f"{self._config['ELASTIC_PASSWORD']}"
            )
            encoded = base64.b64encode(creds.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
        return headers

    @property
    def _verify_ssl(self) -> bool:
        return self._config.get(
            "ELASTIC_VERIFY_SSL", "true"
        ).lower() in ("true", "1", "yes")

    # ------------------------------------------------------------------
    # ECS mapping
    # ------------------------------------------------------------------

    def _map_to_ecs(self, event: dict[str, Any]) -> dict[str, Any]:
        """Map a normalized CyberArmor.ai event to Elastic Common Schema."""
        severity = event.get("severity", "info")
        ecs_severity = _SEVERITY_TO_ECS.get(severity, _SEVERITY_TO_ECS["info"])

        doc: dict[str, Any] = {
            "@timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "event": {
                "id": event.get("event_id", ""),
                "kind": "alert" if severity in ("critical", "high") else "event",
                "category": ["intrusion_detection"],
                "type": ["info"],
                "severity": ecs_severity["event.severity"],
                "risk_score": ecs_severity["event.risk_score"],
                "created": event.get("timestamp", ""),
                "ingested": event.get("ingested_at", datetime.now(timezone.utc).isoformat()),
                "module": "aishields",
                "dataset": f"aishields.{event.get('event_type', 'generic')}",
                "provider": event.get("source_service", "unknown"),
            },
            "message": f"{event.get('title', '')}: {event.get('description', '')}",
            "tags": event.get("tags", []),
            "observer": {
                "product": event.get("product", "CyberArmor.ai Protect"),
                "vendor": "CyberArmor.ai",
                "version": event.get("product_version", "1.0.0"),
            },
            "organization": {
                "id": event.get("tenant_id", ""),
            },
            "rule": {
                "name": event.get("title", ""),
                "description": event.get("description", ""),
                "category": event.get("event_type", ""),
            },
            "aishields": {
                "source_service": event.get("source_service", ""),
                "event_type": event.get("event_type", ""),
                "schema_version": event.get("schema_version", "1.0"),
                "details": event.get("details", {}),
            },
        }

        return doc

    # ------------------------------------------------------------------
    # ILM / Template bootstrapping
    # ------------------------------------------------------------------

    async def _bootstrap_template(self) -> None:
        """Create ILM policy and index template if they do not exist.

        This is called once on first send to ensure the target index
        has the correct mappings and lifecycle.
        """
        if self.__class__._template_bootstrapped:
            return

        if self._config.get("ELASTIC_SKIP_BOOTSTRAP", "false").lower() in (
            "true", "1", "yes",
        ):
            self.__class__._template_bootstrapped = True
            return

        async with httpx.AsyncClient(
            verify=self._verify_ssl, timeout=30.0
        ) as client:
            # 1. Create ILM policy
            ilm_url = f"{self._base_url}/_ilm/policy/{self._index_prefix}-ilm"
            try:
                resp = await client.put(
                    ilm_url,
                    headers={
                        **self._auth_headers,
                        "Content-Type": "application/json",
                    },
                    content=json.dumps(_DEFAULT_ILM_POLICY),
                )
                if resp.status_code in (200, 201):
                    logger.info("Created ILM policy: %s-ilm", self._index_prefix)
                elif resp.status_code == 409:
                    logger.debug("ILM policy already exists")
                else:
                    logger.warning(
                        "ILM policy creation returned %d: %s",
                        resp.status_code,
                        resp.text,
                    )
            except Exception as exc:
                logger.warning("Failed to create ILM policy: %s", exc)

            # 2. Create index template
            template_url = (
                f"{self._base_url}/_index_template/{self._index_prefix}-template"
            )
            try:
                template = _INDEX_TEMPLATE.copy()
                template["index_patterns"] = [f"{self._index_prefix}-*"]
                template["template"]["settings"]["index.lifecycle.name"] = (
                    f"{self._index_prefix}-ilm"
                )
                template["template"]["settings"]["index.lifecycle.rollover_alias"] = (
                    self._index_prefix
                )

                resp = await client.put(
                    template_url,
                    headers={
                        **self._auth_headers,
                        "Content-Type": "application/json",
                    },
                    content=json.dumps(template),
                )
                if resp.status_code in (200, 201):
                    logger.info(
                        "Created index template: %s-template", self._index_prefix
                    )
                else:
                    logger.warning(
                        "Index template creation returned %d: %s",
                        resp.status_code,
                        resp.text,
                    )
            except Exception as exc:
                logger.warning("Failed to create index template: %s", exc)

        self.__class__._template_bootstrapped = True

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    def _current_index(self) -> str:
        """Return the current write index (date-based pattern)."""
        date_suffix = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        return f"{self._index_prefix}-{date_suffix}"

    async def send_event(self, event: dict[str, Any]) -> None:
        await self.send_batch([event])

    async def send_batch(self, events: list[dict[str, Any]]) -> None:
        """Send events using the Elasticsearch Bulk API (NDJSON format)."""
        await self._bootstrap_template()

        index = self._current_index()
        lines: list[str] = []

        for event in events:
            ecs_doc = self._map_to_ecs(event)
            action = {"index": {"_index": index}}
            if self._pipeline:
                action["index"]["pipeline"] = self._pipeline
            lines.append(json.dumps(action))
            lines.append(json.dumps(ecs_doc))

        # Bulk API requires a trailing newline
        body = "\n".join(lines) + "\n"

        url = f"{self._base_url}/_bulk"
        async with httpx.AsyncClient(
            verify=self._verify_ssl, timeout=60.0
        ) as client:
            resp = await client.post(url, headers=self._auth_headers, content=body)

            if resp.status_code not in (200, 201):
                logger.error(
                    "Elasticsearch Bulk API returned %d: %s",
                    resp.status_code,
                    resp.text,
                )
                raise ConnectionError(
                    f"Elasticsearch Bulk API error {resp.status_code}: {resp.text}"
                )

            result = resp.json()
            if result.get("errors"):
                error_items = [
                    item
                    for item in result.get("items", [])
                    if "error" in item.get("index", {})
                ]
                logger.error(
                    "Elasticsearch Bulk API reported %d errors out of %d items",
                    len(error_items),
                    len(events),
                )
                if error_items:
                    logger.error(
                        "First error: %s",
                        json.dumps(error_items[0]["index"]["error"]),
                    )
                raise ConnectionError(
                    f"Elasticsearch Bulk API: {len(error_items)} indexing errors"
                )

            logger.info(
                "Indexed %d events to Elasticsearch index %s",
                len(events),
                index,
            )

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    async def test_connection(self) -> bool:
        """Verify connectivity by calling the cluster info endpoint."""
        try:
            url = f"{self._base_url}/"
            headers = {
                **self._auth_headers,
                "Content-Type": "application/json",
            }
            async with httpx.AsyncClient(
                verify=self._verify_ssl, timeout=10.0
            ) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    info = resp.json()
                    logger.info(
                        "Connected to Elasticsearch cluster '%s' version %s",
                        info.get("cluster_name", "unknown"),
                        info.get("version", {}).get("number", "unknown"),
                    )
                    return True
                return False
        except Exception as exc:
            logger.warning("Elasticsearch connectivity test failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    @classmethod
    def get_config_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "required": [],
            "properties": {
                "ELASTIC_URL": {
                    "type": "string",
                    "description": (
                        "Elasticsearch URL (e.g. https://es-host:9200). "
                        "Required if ELASTIC_CLOUD_ID is not set."
                    ),
                },
                "ELASTIC_CLOUD_ID": {
                    "type": "string",
                    "description": "Elastic Cloud deployment ID.",
                },
                "ELASTIC_API_KEY": {
                    "type": "string",
                    "description": (
                        "Elasticsearch API key (base64-encoded id:api_key)."
                    ),
                },
                "ELASTIC_USERNAME": {
                    "type": "string",
                    "description": "Elasticsearch username for basic auth.",
                },
                "ELASTIC_PASSWORD": {
                    "type": "string",
                    "description": "Elasticsearch password for basic auth.",
                },
                "ELASTIC_INDEX_PREFIX": {
                    "type": "string",
                    "description": (
                        "Index name prefix (default: aishields-protect)."
                    ),
                },
                "ELASTIC_PIPELINE": {
                    "type": "string",
                    "description": "Ingest pipeline name to apply on index.",
                },
                "ELASTIC_VERIFY_SSL": {
                    "type": "string",
                    "description": "Verify TLS certificates (default: true).",
                },
                "ELASTIC_SKIP_BOOTSTRAP": {
                    "type": "string",
                    "description": (
                        "Skip automatic ILM policy and index template "
                        "creation (default: false)."
                    ),
                },
            },
        }
