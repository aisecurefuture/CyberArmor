"""CyberArmor ROS2 Security Node -- Main entry point.

Provides real-time security monitoring for ROS2-based robotic systems.
Subscribes to configurable topics for inspection, publishes security events
to ``/cyberarmor/events``, synchronises policies with the CyberArmor control
plane, and enforces topic-level access control and actuator rate limiting.

ROS2 Parameters
---------------
control_plane_url : str
    Base URL of the CyberArmor control plane (default ``https://localhost:8000``).
agent_api_key : str
    API key for control-plane authentication.
tenant_id : str
    Tenant identifier.
policy_sync_interval_sec : float
    Seconds between policy refreshes (default 60.0).
monitored_topics : list[str]
    Explicit list of topics to monitor; empty = auto-discover all.
enable_topic_monitor : bool (default True)
enable_service_guard : bool (default True)
enable_dds_inspector : bool (default True)
enable_actuator_policy : bool (default True)
enable_sensor_integrity : bool (default True)
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import rclpy
from rclpy.node import Node
from rclpy.parameter import Parameter
from rclpy.qos import (
    DurabilityPolicy,
    HistoryPolicy,
    QoSProfile,
    ReliabilityPolicy,
)
from std_msgs.msg import String

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("cyberarmor.ros_node")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AGENT_VERSION = "1.0.0"
DEFAULT_CONTROL_PLANE_URL = "https://localhost:8000"
DEFAULT_POLICY_SYNC_INTERVAL = 60.0
EVENTS_TOPIC = "/cyberarmor/events"
STATUS_TOPIC = "/cyberarmor/status"

# QoS profile for security events -- reliable + transient-local so late
# subscribers still receive the last N events.
SECURITY_QOS = QoSProfile(
    reliability=ReliabilityPolicy.RELIABLE,
    durability=DurabilityPolicy.TRANSIENT_LOCAL,
    history=HistoryPolicy.KEEP_LAST,
    depth=100,
)

# QoS for monitoring -- best-effort so we never slow the monitored system.
MONITOR_QOS = QoSProfile(
    reliability=ReliabilityPolicy.BEST_EFFORT,
    durability=DurabilityPolicy.VOLATILE,
    history=HistoryPolicy.KEEP_LAST,
    depth=10,
)


# ---------------------------------------------------------------------------
# Security event envelope
# ---------------------------------------------------------------------------

def _make_event(
    severity: str,
    category: str,
    description: str,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a canonical security event dict."""
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,       # INFO, WARNING, CRITICAL, EMERGENCY
        "category": category,       # e.g. topic_access, rate_limit, anomaly
        "description": description,
        "details": details or {},
        "agent": "ros-agent",
        "agent_version": AGENT_VERSION,
    }


# ---------------------------------------------------------------------------
# Main ROS2 Node
# ---------------------------------------------------------------------------

class CyberArmorROSNode(Node):
    """Central security node for CyberArmor ROS2 integration.

    Responsibilities:
    * Publish security events on ``/cyberarmor/events`` (JSON-encoded
      ``std_msgs/String``).
    * Periodically sync policies from the control plane.
    * Enforce topic-level access policies (allow/deny per node).
    * Rate-limit actuator commands.
    * Coordinate sub-modules (topic_monitor, service_guard, etc.).
    """

    def __init__(self) -> None:
        super().__init__("cyberarmor_security_node")

        # -- Declare ROS2 parameters ---------------------------------------
        self.declare_parameter("control_plane_url", DEFAULT_CONTROL_PLANE_URL)
        self.declare_parameter("agent_api_key", "")
        self.declare_parameter("tenant_id", "")
        self.declare_parameter("agent_id", str(uuid.uuid4()))
        self.declare_parameter("policy_sync_interval_sec", DEFAULT_POLICY_SYNC_INTERVAL)
        self.declare_parameter("monitored_topics", [""])
        self.declare_parameter("enable_topic_monitor", True)
        self.declare_parameter("enable_service_guard", True)
        self.declare_parameter("enable_dds_inspector", True)
        self.declare_parameter("enable_actuator_policy", True)
        self.declare_parameter("enable_sensor_integrity", True)
        self.declare_parameter("actuator_rate_limit_hz", 50.0)
        self.declare_parameter("log_level", "INFO")

        # -- Read parameters ------------------------------------------------
        self._control_plane_url: str = self.get_parameter(
            "control_plane_url"
        ).get_parameter_value().string_value
        self._api_key: str = self.get_parameter(
            "agent_api_key"
        ).get_parameter_value().string_value
        self._tenant_id: str = self.get_parameter(
            "tenant_id"
        ).get_parameter_value().string_value
        self._agent_id: str = self.get_parameter(
            "agent_id"
        ).get_parameter_value().string_value
        self._policy_sync_interval: float = self.get_parameter(
            "policy_sync_interval_sec"
        ).get_parameter_value().double_value
        self._monitored_topics: List[str] = [
            t for t in self.get_parameter(
                "monitored_topics"
            ).get_parameter_value().string_array_value if t
        ]

        log_level = self.get_parameter("log_level").get_parameter_value().string_value
        logging.getLogger().setLevel(getattr(logging, log_level.upper(), logging.INFO))

        # -- State ----------------------------------------------------------
        self._policies: List[Dict[str, Any]] = []
        self._policies_lock = threading.Lock()
        self._topic_access_rules: Dict[str, Dict[str, str]] = {}  # topic -> {node: allow/deny}
        self._rate_limiters: Dict[str, _TokenBucket] = {}
        self._subscriptions_map: Dict[str, Any] = {}  # topic -> subscription
        self._running = True

        # -- Publishers -----------------------------------------------------
        self._event_pub = self.create_publisher(String, EVENTS_TOPIC, SECURITY_QOS)
        self._status_pub = self.create_publisher(String, STATUS_TOPIC, SECURITY_QOS)

        # -- Sub-modules (lazy-loaded) --------------------------------------
        self._topic_monitor = None
        self._service_guard = None
        self._dds_inspector = None
        self._actuator_policy = None
        self._sensor_integrity = None

        # -- Timers ---------------------------------------------------------
        self._policy_sync_timer = self.create_timer(
            self._policy_sync_interval, self._policy_sync_callback
        )
        self._status_timer = self.create_timer(10.0, self._publish_status)

        # -- Dynamic parameter callback ------------------------------------
        self.add_on_set_parameters_callback(self._on_param_change)

        # -- Initial policy sync (background thread) -----------------------
        self._sync_thread = threading.Thread(
            target=self._initial_sync, daemon=True
        )
        self._sync_thread.start()

        # -- Start sub-modules ---------------------------------------------
        self._start_submodules()

        self.get_logger().info(
            "CyberArmor ROS2 Security Node v%s started  agent_id=%s",
            AGENT_VERSION,
            self._agent_id,
        )

    # ------------------------------------------------------------------
    # Sub-module lifecycle
    # ------------------------------------------------------------------

    def _start_submodules(self) -> None:
        """Instantiate and start enabled sub-modules."""
        if self.get_parameter("enable_topic_monitor").get_parameter_value().bool_value:
            try:
                from topic_monitor import TopicMonitor

                self._topic_monitor = TopicMonitor(self)
                self.get_logger().info("TopicMonitor started")
            except Exception as exc:
                self.get_logger().error("Failed to start TopicMonitor: %s", exc)

        if self.get_parameter("enable_service_guard").get_parameter_value().bool_value:
            try:
                from service_guard import ServiceGuard

                self._service_guard = ServiceGuard(self)
                self.get_logger().info("ServiceGuard started")
            except Exception as exc:
                self.get_logger().error("Failed to start ServiceGuard: %s", exc)

        if self.get_parameter("enable_dds_inspector").get_parameter_value().bool_value:
            try:
                from dds_inspector import DDSInspector

                self._dds_inspector = DDSInspector(self)
                self.get_logger().info("DDSInspector started")
            except Exception as exc:
                self.get_logger().error("Failed to start DDSInspector: %s", exc)

        if self.get_parameter("enable_actuator_policy").get_parameter_value().bool_value:
            try:
                from actuator_policy import ActuatorPolicyEnforcer

                rate_hz = self.get_parameter(
                    "actuator_rate_limit_hz"
                ).get_parameter_value().double_value
                self._actuator_policy = ActuatorPolicyEnforcer(self, max_rate_hz=rate_hz)
                self.get_logger().info("ActuatorPolicyEnforcer started")
            except Exception as exc:
                self.get_logger().error("Failed to start ActuatorPolicyEnforcer: %s", exc)

        if self.get_parameter("enable_sensor_integrity").get_parameter_value().bool_value:
            try:
                from sensor_integrity import SensorIntegrityMonitor

                self._sensor_integrity = SensorIntegrityMonitor(self)
                self.get_logger().info("SensorIntegrityMonitor started")
            except Exception as exc:
                self.get_logger().error("Failed to start SensorIntegrityMonitor: %s", exc)

    # ------------------------------------------------------------------
    # Event publishing
    # ------------------------------------------------------------------

    def publish_event(
        self,
        severity: str,
        category: str,
        description: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Publish a security event on /cyberarmor/events."""
        event = _make_event(severity, category, description, details)
        msg = String()
        msg.data = json.dumps(event)
        self._event_pub.publish(msg)
        self.get_logger().info(
            "[%s] %s: %s", severity, category, description
        )

    # ------------------------------------------------------------------
    # Policy sync
    # ------------------------------------------------------------------

    def _initial_sync(self) -> None:
        """Blocking initial policy sync executed in a background thread."""
        time.sleep(2.0)  # wait for network / control-plane readiness
        self._do_policy_sync()

    def _policy_sync_callback(self) -> None:
        """Timer callback -- trigger a background policy sync."""
        threading.Thread(target=self._do_policy_sync, daemon=True).start()

    def _do_policy_sync(self) -> None:
        """Fetch policies from the control plane (runs in background thread)."""
        if not _HAS_HTTPX or not self._api_key:
            self.get_logger().debug("Skipping policy sync (no httpx or api key)")
            return

        url = f"{self._control_plane_url}/policies/{self._tenant_id}"
        headers = {"x-api-key": self._api_key, "Content-Type": "application/json"}
        try:
            with httpx.Client(timeout=10.0, headers=headers, verify=True) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    policies = resp.json()
                    with self._policies_lock:
                        self._policies = policies
                        self._rebuild_access_rules(policies)
                    self.get_logger().info(
                        "Policy sync complete: %d policies", len(policies)
                    )
                else:
                    self.get_logger().warning(
                        "Policy sync failed status=%s", resp.status_code
                    )
        except Exception as exc:
            self.get_logger().error("Policy sync error: %s", exc)

    def _rebuild_access_rules(self, policies: List[Dict[str, Any]]) -> None:
        """Extract topic access rules from fetched policies."""
        self._topic_access_rules.clear()
        for policy in policies:
            if policy.get("type") != "ros_topic_access":
                continue
            rules = policy.get("rules", {})
            for topic, perms in rules.items():
                self._topic_access_rules[topic] = perms  # {node_name: allow|deny}

    # ------------------------------------------------------------------
    # Topic access enforcement
    # ------------------------------------------------------------------

    def check_topic_access(self, topic: str, node_name: str) -> bool:
        """Return True if *node_name* is allowed to access *topic*.

        Deny takes precedence.  If no rule exists the default is allow.
        """
        rules = self._topic_access_rules.get(topic)
        if rules is None:
            return True  # no rule = allow
        action = rules.get(node_name, rules.get("*", "allow"))
        allowed = action.lower() != "deny"
        if not allowed:
            self.publish_event(
                "WARNING",
                "topic_access",
                f"Denied access to {topic} for node {node_name}",
                {"topic": topic, "node": node_name, "action": "deny"},
            )
        return allowed

    # ------------------------------------------------------------------
    # Actuator rate limiting (token-bucket)
    # ------------------------------------------------------------------

    def check_actuator_rate(self, topic: str, max_hz: Optional[float] = None) -> bool:
        """Return True if a command on *topic* is within the rate limit."""
        if max_hz is None:
            max_hz = self.get_parameter(
                "actuator_rate_limit_hz"
            ).get_parameter_value().double_value
        if topic not in self._rate_limiters:
            self._rate_limiters[topic] = _TokenBucket(rate=max_hz, capacity=max_hz * 2)
        bucket = self._rate_limiters[topic]
        if bucket.consume():
            return True
        self.publish_event(
            "WARNING",
            "rate_limit",
            f"Actuator rate limit exceeded on {topic}",
            {"topic": topic, "max_hz": max_hz},
        )
        return False

    # ------------------------------------------------------------------
    # Status publishing
    # ------------------------------------------------------------------

    def _publish_status(self) -> None:
        """Periodic heartbeat / status message."""
        status = {
            "agent_id": self._agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "policies_loaded": len(self._policies),
            "monitored_topics": list(self._subscriptions_map.keys()),
            "submodules": {
                "topic_monitor": self._topic_monitor is not None,
                "service_guard": self._service_guard is not None,
                "dds_inspector": self._dds_inspector is not None,
                "actuator_policy": self._actuator_policy is not None,
                "sensor_integrity": self._sensor_integrity is not None,
            },
            "version": AGENT_VERSION,
        }
        msg = String()
        msg.data = json.dumps(status)
        self._status_pub.publish(msg)

    # ------------------------------------------------------------------
    # Dynamic parameter handling
    # ------------------------------------------------------------------

    def _on_param_change(self, params: List[Parameter]) -> rclpy.parameter.SetParametersResult:
        """Handle dynamic parameter changes."""
        from rclpy.parameter import SetParametersResult

        for param in params:
            if param.name == "policy_sync_interval_sec":
                self._policy_sync_interval = param.value
                self._policy_sync_timer.cancel()
                self._policy_sync_timer = self.create_timer(
                    self._policy_sync_interval, self._policy_sync_callback
                )
                self.get_logger().info(
                    "Policy sync interval changed to %.1fs", param.value
                )
            elif param.name == "log_level":
                logging.getLogger().setLevel(
                    getattr(logging, str(param.value).upper(), logging.INFO)
                )
        return SetParametersResult(successful=True)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def policies(self) -> List[Dict[str, Any]]:
        with self._policies_lock:
            return list(self._policies)

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def destroy_node(self) -> None:
        self._running = False
        self.get_logger().info("CyberArmor ROS2 Security Node shutting down")
        super().destroy_node()


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------

class _TokenBucket:
    """Simple token-bucket rate limiter (thread-safe)."""

    def __init__(self, rate: float, capacity: float) -> None:
        self._rate = rate          # tokens / second
        self._capacity = capacity
        self._tokens = capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(args=None) -> None:
    rclpy.init(args=args)
    node = CyberArmorROSNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main()
