"""AIShields DDS (Data Distribution Service) Layer Inspector.

Monitors the DDS discovery protocol underpinning ROS2 to detect unauthorised
participants, QoS policy violations, and DDS security-plugin status.

DDS Concepts
------------
* **Participant**: A DDS entity representing a single process on the network.
  Each ROS2 node is backed by one or more DDS participants.
* **Discovery**: The SPDP/SEDP protocols used by DDS to find participants,
  readers and writers on the network.
* **QoS**: Quality-of-Service settings that control reliability, durability,
  deadline, lifespan, etc.

This module uses the ROS2 graph introspection API (which queries the
underlying DDS layer) to:
1. Enumerate all DDS participants visible on the domain.
2. Detect new / disappearing participants.
3. Cross-check participants against an approved-nodes allow-list.
4. Inspect QoS profiles for compliance with security policy.
5. Report on the DDS security-plugin status when available.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from rclpy.node import Node

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
INSPECTION_INTERVAL_SEC = 10.0
QOS_CHECK_INTERVAL_SEC = 30.0


@dataclass
class ParticipantRecord:
    """Record of a discovered DDS participant."""
    gid: str                              # unique identifier
    node_name: str = ""
    node_namespace: str = ""
    host: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    authorised: Optional[bool] = None     # None = not yet checked
    qos_violations: List[str] = field(default_factory=list)


class DDSInspector:
    """Inspect and monitor the DDS discovery layer.

    Parameters
    ----------
    node : Node
        Parent AIShieldsROSNode.
    """

    def __init__(self, node: Node) -> None:
        self._node = node
        self._participants: Dict[str, ParticipantRecord] = {}
        self._known_gids: Set[str] = set()
        self._lock = threading.Lock()

        # Policy: set of allowed node FQDNs (/namespace/node_name)
        self._allowed_nodes: Set[str] = set()
        self._deny_nodes: Set[str] = set()

        # QoS compliance rules: list of {topic_pattern, required_qos}
        self._qos_rules: List[Dict[str, Any]] = []

        # DDS security plugin expected status
        self._expect_security_plugin: bool = False

        # Timers
        self._inspect_timer = node.create_timer(
            INSPECTION_INTERVAL_SEC, self._inspect_participants
        )
        self._qos_timer = node.create_timer(
            QOS_CHECK_INTERVAL_SEC, self._check_qos_compliance
        )

        node.get_logger().info("DDSInspector initialised")

    # ------------------------------------------------------------------
    # Participant inspection
    # ------------------------------------------------------------------

    def _inspect_participants(self) -> None:
        """Enumerate participants via the ROS2 graph API."""
        try:
            node_names_and_ns: List[Tuple[str, str]] = (
                self._node.get_node_names_and_namespaces()
            )
        except Exception as exc:
            self._node.get_logger().debug("Participant inspection error: %s", exc)
            return

        now = time.monotonic()
        current_gids: Set[str] = set()

        for node_name, namespace in node_names_and_ns:
            fqdn = f"{namespace}/{node_name}".replace("//", "/")
            gid = self._make_gid(fqdn)
            current_gids.add(gid)

            with self._lock:
                if gid not in self._participants:
                    record = ParticipantRecord(
                        gid=gid,
                        node_name=node_name,
                        node_namespace=namespace,
                        first_seen=now,
                        last_seen=now,
                    )
                    record.authorised = self._check_authorised(fqdn)
                    self._participants[gid] = record

                    if record.authorised is False:
                        self._publish_event(
                            "CRITICAL",
                            "unauthorised_participant",
                            f"Unauthorised DDS participant: {fqdn}",
                            {
                                "gid": gid,
                                "node": node_name,
                                "namespace": namespace,
                                "fqdn": fqdn,
                            },
                        )
                    else:
                        self._publish_event(
                            "INFO",
                            "participant_joined",
                            f"DDS participant joined: {fqdn}",
                            {"gid": gid, "fqdn": fqdn},
                        )
                else:
                    self._participants[gid].last_seen = now

        # Detect departures
        with self._lock:
            departed = self._known_gids - current_gids
            for gid in departed:
                record = self._participants.pop(gid, None)
                if record:
                    fqdn = f"{record.node_namespace}/{record.node_name}"
                    self._publish_event(
                        "WARNING",
                        "participant_left",
                        f"DDS participant left: {fqdn}",
                        {"gid": gid, "fqdn": fqdn},
                    )
            self._known_gids = current_gids

    # ------------------------------------------------------------------
    # Authorisation check
    # ------------------------------------------------------------------

    def _check_authorised(self, fqdn: str) -> Optional[bool]:
        """Check whether a participant FQDN is authorised.

        Returns None if no allow/deny lists are configured (all are permitted).
        """
        if not self._allowed_nodes and not self._deny_nodes:
            return None  # no policy loaded

        if fqdn in self._deny_nodes:
            return False
        if self._allowed_nodes and fqdn not in self._allowed_nodes:
            return False
        return True

    # ------------------------------------------------------------------
    # QoS compliance
    # ------------------------------------------------------------------

    def _check_qos_compliance(self) -> None:
        """Check topic QoS profiles against policy requirements."""
        if not self._qos_rules:
            return

        try:
            topics = self._node.get_topic_names_and_types()
        except Exception:
            return

        import fnmatch

        for topic_name, _ in topics:
            for rule in self._qos_rules:
                pattern = rule.get("topic_pattern", "")
                if not fnmatch.fnmatch(topic_name, pattern):
                    continue

                required_qos = rule.get("required_qos", {})
                # Inspect publishers QoS
                try:
                    pub_info = self._node.get_publishers_info_by_topic(topic_name)
                except Exception:
                    continue

                for pub in pub_info:
                    violations = self._check_endpoint_qos(
                        pub.qos_profile, required_qos, topic_name, pub.node_name
                    )
                    if violations:
                        self._publish_event(
                            "WARNING",
                            "qos_violation",
                            f"QoS violation on {topic_name} by {pub.node_name}",
                            {
                                "topic": topic_name,
                                "node": pub.node_name,
                                "violations": violations,
                                "rule_pattern": pattern,
                            },
                        )

    def _check_endpoint_qos(
        self,
        qos: Any,
        required: Dict[str, Any],
        topic: str,
        node_name: str,
    ) -> List[str]:
        """Compare an endpoint's QoS against required values."""
        violations: List[str] = []

        if "reliability" in required:
            expected = required["reliability"].upper()
            actual = str(getattr(qos, "reliability", "")).upper()
            if expected not in actual:
                violations.append(
                    f"reliability: expected {expected}, got {actual}"
                )

        if "durability" in required:
            expected = required["durability"].upper()
            actual = str(getattr(qos, "durability", "")).upper()
            if expected not in actual:
                violations.append(
                    f"durability: expected {expected}, got {actual}"
                )

        if "deadline_ms" in required:
            try:
                deadline = qos.deadline
                if hasattr(deadline, "nanoseconds"):
                    actual_ms = deadline.nanoseconds / 1_000_000
                    if actual_ms > required["deadline_ms"]:
                        violations.append(
                            f"deadline: {actual_ms:.0f}ms > {required['deadline_ms']}ms"
                        )
            except Exception:
                pass

        if "lifespan_ms" in required:
            try:
                lifespan = qos.lifespan
                if hasattr(lifespan, "nanoseconds"):
                    actual_ms = lifespan.nanoseconds / 1_000_000
                    if actual_ms > required["lifespan_ms"]:
                        violations.append(
                            f"lifespan: {actual_ms:.0f}ms > {required['lifespan_ms']}ms"
                        )
            except Exception:
                pass

        return violations

    # ------------------------------------------------------------------
    # DDS Security Plugin status
    # ------------------------------------------------------------------

    def check_security_plugin_status(self) -> Dict[str, Any]:
        """Report on DDS security plugin availability.

        Returns a status dict.  Full security-plugin introspection requires
        vendor-specific DDS APIs; this method provides a best-effort check.
        """
        status: Dict[str, Any] = {
            "expected": self._expect_security_plugin,
            "detected": False,
            "details": {},
        }

        # Attempt to detect security plugin via environment and known DDS config
        import os

        # Fast RTPS / CycloneDDS security governance file
        governance_file = os.environ.get("ROS_SECURITY_GOVERNANCE_FILE", "")
        permissions_file = os.environ.get("ROS_SECURITY_PERMISSIONS_FILE", "")
        security_enabled = os.environ.get("ROS_SECURITY_ENABLE", "false").lower()
        security_strategy = os.environ.get("ROS_SECURITY_STRATEGY", "")

        if security_enabled in ("true", "1", "yes"):
            status["detected"] = True
            status["details"] = {
                "security_enabled": True,
                "strategy": security_strategy,
                "governance_file": governance_file,
                "permissions_file": permissions_file,
            }
        else:
            status["details"] = {
                "security_enabled": False,
                "note": "ROS_SECURITY_ENABLE not set to true",
            }

        if self._expect_security_plugin and not status["detected"]:
            self._publish_event(
                "CRITICAL",
                "security_plugin_missing",
                "DDS security plugin expected but not detected",
                status,
            )

        return status

    # ------------------------------------------------------------------
    # Policy management
    # ------------------------------------------------------------------

    def update_policies(self, policies: List[Dict[str, Any]]) -> None:
        """Update DDS inspector policies from control-plane sync."""
        self._allowed_nodes.clear()
        self._deny_nodes.clear()
        self._qos_rules.clear()

        for p in policies:
            ptype = p.get("type", "")
            if ptype == "dds_participant_access":
                for node in p.get("allowed_nodes", []):
                    self._allowed_nodes.add(node)
                for node in p.get("denied_nodes", []):
                    self._deny_nodes.add(node)
            elif ptype == "dds_qos_compliance":
                self._qos_rules.extend(p.get("rules", []))
            elif ptype == "dds_security_plugin":
                self._expect_security_plugin = p.get("require_plugin", False)

        self._node.get_logger().info(
            "DDSInspector policies updated: %d allowed, %d denied, %d QoS rules",
            len(self._allowed_nodes),
            len(self._deny_nodes),
            len(self._qos_rules),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_gid(fqdn: str) -> str:
        """Derive a deterministic GID from a fully-qualified node name."""
        return hashlib.sha256(fqdn.encode()).hexdigest()[:16]

    def _publish_event(
        self,
        severity: str,
        category: str,
        description: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        if hasattr(self._node, "publish_event"):
            self._node.publish_event(severity, category, description, details)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_participants(self) -> List[Dict[str, Any]]:
        """Return all currently tracked participants."""
        with self._lock:
            return [
                {
                    "gid": r.gid,
                    "node_name": r.node_name,
                    "namespace": r.node_namespace,
                    "authorised": r.authorised,
                    "first_seen": r.first_seen,
                    "last_seen": r.last_seen,
                    "qos_violations": r.qos_violations,
                }
                for r in self._participants.values()
            ]
