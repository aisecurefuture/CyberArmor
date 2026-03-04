"""AIShields ROS2 Service Guard.

Monitors and guards ROS2 service calls to safety-critical services.
Validates request parameters against configurable policies, logs all service
interactions, and blocks unauthorised service access.

Architecture
------------
ROS2 does not natively support "intercepting" a service call in the same way
a network proxy does.  Instead the ServiceGuard:

1. Periodically discovers all services on the graph.
2. Maintains a shadow client for each guarded service so it can inspect
   availability and metadata.
3. For *new* services, publishes security events and cross-checks against
   the allow/deny list from the control-plane policy.
4. Exposes a ``/aishields/service_guard/validate`` service that other nodes
   can call *before* issuing a safety-critical request to get pre-approval.
"""

from __future__ import annotations

import fnmatch
import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from rclpy.node import Node
from std_msgs.msg import String

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DISCOVERY_INTERVAL_SEC = 5.0
AUDIT_LOG_MAX_SIZE = 10_000  # in-memory ring buffer

# Services we never guard
_IGNORE_PREFIXES = (
    "/aishields/",
    "/rosout/",
    "/_",
    "/get_parameters",
    "/set_parameters",
    "/describe_parameters",
    "/list_parameters",
    "/get_parameter_types",
)

# Safety-critical service patterns (glob)
_DEFAULT_CRITICAL_PATTERNS = [
    "*/arm/*",
    "*/gripper/*",
    "*/motor/*",
    "*/estop*",
    "*/emergency*",
    "*/launch*",
    "*/kill*",
    "*/shutdown*",
    "*/reboot*",
    "*/set_mode*",
    "*/set_param*",
]


@dataclass
class ServiceAuditEntry:
    """Single entry in the service audit log."""
    timestamp: float
    service_name: str
    caller_node: str
    request_summary: str
    decision: str      # allow / deny / warn
    policy_matched: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ServiceInfo:
    """Tracked information about a discovered service."""
    name: str
    service_type: str
    server_nodes: Set[str] = field(default_factory=set)
    is_critical: bool = False
    call_count: int = 0
    last_seen: float = 0.0
    denied_count: int = 0


class ServiceGuard:
    """Guard for ROS2 service calls.

    Parameters
    ----------
    node : Node
        Parent AIShieldsROSNode.
    """

    def __init__(self, node: Node) -> None:
        self._node = node
        self._services: Dict[str, ServiceInfo] = {}
        self._known_services: Set[str] = set()
        self._lock = threading.Lock()

        # Audit ring buffer
        self._audit_log: List[ServiceAuditEntry] = []
        self._audit_lock = threading.Lock()

        # Policy: service_name_pattern -> {action, allowed_callers, param_constraints}
        self._service_policies: Dict[str, Dict[str, Any]] = {}
        # Default critical patterns
        self._critical_patterns: List[str] = list(_DEFAULT_CRITICAL_PATTERNS)

        # Timer for discovery
        self._discovery_timer = node.create_timer(
            DISCOVERY_INTERVAL_SEC, self._discovery_scan
        )

        node.get_logger().info("ServiceGuard initialised")

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _discovery_scan(self) -> None:
        """Discover services and detect changes."""
        try:
            service_list = self._node.get_service_names_and_types()
        except Exception as exc:
            self._node.get_logger().debug("Service discovery error: %s", exc)
            return

        current: Set[str] = set()
        for svc_name, svc_types in service_list:
            if any(svc_name.startswith(p) for p in _IGNORE_PREFIXES):
                continue
            current.add(svc_name)
            svc_type = svc_types[0] if svc_types else "unknown"

            with self._lock:
                if svc_name not in self._services:
                    is_critical = self._is_critical(svc_name)
                    self._services[svc_name] = ServiceInfo(
                        name=svc_name,
                        service_type=svc_type,
                        is_critical=is_critical,
                        last_seen=time.monotonic(),
                    )
                    severity = "WARNING" if is_critical else "INFO"
                    self._publish_event(
                        severity,
                        "service_discovered",
                        f"New service: {svc_name} [{svc_type}]"
                        + (" (CRITICAL)" if is_critical else ""),
                        {"service": svc_name, "type": svc_type, "critical": is_critical},
                    )
                else:
                    self._services[svc_name].last_seen = time.monotonic()

        # Detect removed services
        with self._lock:
            disappeared = self._known_services - current
            for svc_name in disappeared:
                self._publish_event(
                    "WARNING",
                    "service_removed",
                    f"Service removed: {svc_name}",
                    {"service": svc_name},
                )
                self._services.pop(svc_name, None)
            self._known_services = current

    # ------------------------------------------------------------------
    # Critical detection
    # ------------------------------------------------------------------

    def _is_critical(self, service_name: str) -> bool:
        """Check if a service matches any critical pattern."""
        for pattern in self._critical_patterns:
            if fnmatch.fnmatch(service_name, pattern):
                return True
        return False

    # ------------------------------------------------------------------
    # Validation API
    # ------------------------------------------------------------------

    def validate_service_call(
        self,
        service_name: str,
        caller_node: str,
        request_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validate whether a service call should be permitted.

        Returns
        -------
        dict
            ``{"allowed": bool, "reason": str, "policy": str}``
        """
        request_params = request_params or {}

        # 1. Check explicit policies
        for pattern, policy in self._service_policies.items():
            if fnmatch.fnmatch(service_name, pattern):
                result = self._evaluate_policy(
                    service_name, caller_node, request_params, policy
                )
                self._audit(
                    service_name, caller_node, request_params,
                    "allow" if result["allowed"] else "deny", pattern,
                )
                return result

        # 2. If no explicit policy, check if critical
        with self._lock:
            svc = self._services.get(service_name)
        if svc and svc.is_critical:
            self._audit(
                service_name, caller_node, request_params,
                "warn", "default_critical",
            )
            self._publish_event(
                "WARNING",
                "service_call_unguarded",
                f"Call to critical service {service_name} by {caller_node} "
                "with no explicit policy",
                {
                    "service": service_name,
                    "caller": caller_node,
                    "params": request_params,
                },
            )
            return {
                "allowed": True,
                "reason": "No explicit policy; critical service warning issued",
                "policy": "default_critical",
            }

        # 3. Default allow for non-critical
        self._audit(
            service_name, caller_node, request_params, "allow", "default",
        )
        return {"allowed": True, "reason": "Default allow", "policy": "default"}

    def _evaluate_policy(
        self,
        service_name: str,
        caller_node: str,
        request_params: Dict[str, Any],
        policy: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Evaluate a single service policy."""
        action = policy.get("action", "allow")

        # Caller allow-list
        allowed_callers = policy.get("allowed_callers", [])
        if allowed_callers and caller_node not in allowed_callers:
            with self._lock:
                svc = self._services.get(service_name)
                if svc:
                    svc.denied_count += 1
            self._publish_event(
                "WARNING",
                "service_access_denied",
                f"Caller {caller_node} not in allow list for {service_name}",
                {
                    "service": service_name,
                    "caller": caller_node,
                    "allowed": allowed_callers,
                },
            )
            return {
                "allowed": False,
                "reason": f"Caller {caller_node} not in allowed list",
                "policy": policy.get("name", "unknown"),
            }

        # Parameter constraints
        constraints = policy.get("param_constraints", {})
        for param_name, constraint in constraints.items():
            value = request_params.get(param_name)
            if value is None:
                continue
            if "min" in constraint and float(value) < constraint["min"]:
                return {
                    "allowed": False,
                    "reason": f"Parameter {param_name}={value} below min {constraint['min']}",
                    "policy": policy.get("name", "unknown"),
                }
            if "max" in constraint and float(value) > constraint["max"]:
                return {
                    "allowed": False,
                    "reason": f"Parameter {param_name}={value} above max {constraint['max']}",
                    "policy": policy.get("name", "unknown"),
                }
            if "allowed_values" in constraint and value not in constraint["allowed_values"]:
                return {
                    "allowed": False,
                    "reason": f"Parameter {param_name}={value} not in allowed values",
                    "policy": policy.get("name", "unknown"),
                }

        if action == "deny":
            return {
                "allowed": False,
                "reason": "Service blocked by policy",
                "policy": policy.get("name", "unknown"),
            }

        return {
            "allowed": True,
            "reason": "Policy passed",
            "policy": policy.get("name", "unknown"),
        }

    # ------------------------------------------------------------------
    # Audit logging
    # ------------------------------------------------------------------

    def _audit(
        self,
        service_name: str,
        caller_node: str,
        request_params: Dict[str, Any],
        decision: str,
        policy_matched: str,
    ) -> None:
        """Append an entry to the in-memory audit ring buffer."""
        entry = ServiceAuditEntry(
            timestamp=time.monotonic(),
            service_name=service_name,
            caller_node=caller_node,
            request_summary=json.dumps(request_params)[:512],
            decision=decision,
            policy_matched=policy_matched,
        )
        with self._audit_lock:
            self._audit_log.append(entry)
            if len(self._audit_log) > AUDIT_LOG_MAX_SIZE:
                self._audit_log = self._audit_log[-AUDIT_LOG_MAX_SIZE:]

    # ------------------------------------------------------------------
    # Policy management
    # ------------------------------------------------------------------

    def update_policies(self, policies: List[Dict[str, Any]]) -> None:
        """Update service-guard policies from the control plane sync."""
        self._service_policies.clear()
        for p in policies:
            if p.get("type") != "ros_service_guard":
                continue
            pattern = p.get("service_pattern", "")
            if pattern:
                self._service_policies[pattern] = p
        self._node.get_logger().info(
            "ServiceGuard policies updated: %d rules", len(self._service_policies)
        )

    def add_critical_pattern(self, pattern: str) -> None:
        """Add a glob pattern that marks matching services as critical."""
        if pattern not in self._critical_patterns:
            self._critical_patterns.append(pattern)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

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

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return recent audit log entries."""
        with self._audit_lock:
            entries = self._audit_log[-limit:]
        return [
            {
                "timestamp": e.timestamp,
                "service": e.service_name,
                "caller": e.caller_node,
                "decision": e.decision,
                "policy": e.policy_matched,
                "request_summary": e.request_summary,
            }
            for e in entries
        ]

    def get_services(self) -> Dict[str, Dict[str, Any]]:
        """Return info about all tracked services."""
        with self._lock:
            return {
                name: {
                    "type": s.service_type,
                    "critical": s.is_critical,
                    "call_count": s.call_count,
                    "denied_count": s.denied_count,
                    "server_nodes": list(s.server_nodes),
                }
                for name, s in self._services.items()
            }
