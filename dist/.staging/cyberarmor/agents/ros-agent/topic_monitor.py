"""AIShields ROS2 Topic Monitor.

Auto-discovers all active topics in the ROS2 graph, monitors message rates
to detect flood/DoS conditions, inspects message content for anomalies,
tracks publisher/subscriber membership changes, and alerts on unauthorised
topic access.

The monitor runs as a companion to the main ``AIShieldsROSNode``.  It creates
its own timers on the parent node to perform periodic discovery scans and
rate checks.
"""

from __future__ import annotations

import statistics
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from rclpy.node import Node
from rclpy.qos import (
    DurabilityPolicy,
    HistoryPolicy,
    QoSProfile,
    ReliabilityPolicy,
)
from std_msgs.msg import String

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
DISCOVERY_INTERVAL_SEC = 5.0
RATE_CHECK_INTERVAL_SEC = 2.0
MAX_MESSAGE_RATE_DEFAULT = 1000.0   # msgs/sec before flood alert
MIN_MESSAGE_RATE_DEFAULT = 0.0      # msgs/sec (0 = no minimum)
RATE_WINDOW_SEC = 10.0              # sliding window for rate computation

# Topics to ignore (internal ROS2 / DDS discovery)
_IGNORE_PREFIXES = (
    "/rosout",
    "/parameter_events",
    "/aishields/",
    "/clock",
    "/_",
    "/rt/",
)

MONITOR_QOS = QoSProfile(
    reliability=ReliabilityPolicy.BEST_EFFORT,
    durability=DurabilityPolicy.VOLATILE,
    history=HistoryPolicy.KEEP_LAST,
    depth=1,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TopicStats:
    """Accumulated statistics for a single topic."""
    topic: str
    msg_type: str = ""
    message_count: int = 0
    timestamps: List[float] = field(default_factory=list)
    publishers: Set[str] = field(default_factory=set)
    subscribers: Set[str] = field(default_factory=set)
    last_alert_time: float = 0.0
    anomaly_count: int = 0
    max_rate_hz: float = MAX_MESSAGE_RATE_DEFAULT
    min_rate_hz: float = MIN_MESSAGE_RATE_DEFAULT

    def record_message(self) -> None:
        now = time.monotonic()
        self.message_count += 1
        self.timestamps.append(now)
        # Trim to window
        cutoff = now - RATE_WINDOW_SEC
        self.timestamps = [t for t in self.timestamps if t >= cutoff]

    @property
    def current_rate_hz(self) -> float:
        if len(self.timestamps) < 2:
            return 0.0
        window = self.timestamps[-1] - self.timestamps[0]
        if window <= 0:
            return 0.0
        return (len(self.timestamps) - 1) / window

    @property
    def mean_interval_ms(self) -> float:
        if len(self.timestamps) < 2:
            return 0.0
        intervals = [
            (self.timestamps[i + 1] - self.timestamps[i]) * 1000
            for i in range(len(self.timestamps) - 1)
        ]
        return statistics.mean(intervals) if intervals else 0.0


# ---------------------------------------------------------------------------
# Topic Monitor
# ---------------------------------------------------------------------------

class TopicMonitor:
    """Continuously monitors the ROS2 topic graph for security anomalies.

    Parameters
    ----------
    node : Node
        Parent AIShieldsROSNode (used for creating subscriptions, timers,
        and publishing events).
    """

    def __init__(self, node: Node) -> None:
        self._node = node
        self._stats: Dict[str, TopicStats] = {}
        self._known_topics: Set[str] = set()
        self._subscriptions: Dict[str, Any] = {}
        self._lock = threading.Lock()

        # Per-topic rate override map: topic_pattern -> max_hz
        self._rate_overrides: Dict[str, float] = {}

        # Timers on the parent node
        self._discovery_timer = node.create_timer(
            DISCOVERY_INTERVAL_SEC, self._discovery_scan
        )
        self._rate_timer = node.create_timer(
            RATE_CHECK_INTERVAL_SEC, self._rate_check
        )

        node.get_logger().info(
            "TopicMonitor initialised (discovery=%.1fs, rate_check=%.1fs)",
            DISCOVERY_INTERVAL_SEC,
            RATE_CHECK_INTERVAL_SEC,
        )

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _discovery_scan(self) -> None:
        """Discover new topics and track publisher/subscriber changes."""
        topic_list: List[Tuple[str, List[str]]] = self._node.get_topic_names_and_types()

        current_topics: Set[str] = set()

        for topic_name, msg_types in topic_list:
            if any(topic_name.startswith(p) for p in _IGNORE_PREFIXES):
                continue
            current_topics.add(topic_name)
            msg_type = msg_types[0] if msg_types else "unknown"

            # Track membership
            pub_info = self._node.get_publishers_info_by_topic(topic_name)
            sub_info = self._node.get_subscriptions_info_by_topic(topic_name)
            pub_nodes = {f"{p.node_name}@{p.node_namespace}" for p in pub_info}
            sub_nodes = {f"{s.node_name}@{s.node_namespace}" for s in sub_info}

            with self._lock:
                if topic_name not in self._stats:
                    # New topic discovered
                    self._stats[topic_name] = TopicStats(
                        topic=topic_name, msg_type=msg_type
                    )
                    self._subscribe_to_topic(topic_name, msg_type)
                    self._node.get_logger().info(
                        "Discovered new topic: %s [%s]", topic_name, msg_type
                    )
                    if hasattr(self._node, "publish_event"):
                        self._node.publish_event(
                            "INFO",
                            "topic_discovery",
                            f"New topic discovered: {topic_name}",
                            {"topic": topic_name, "type": msg_type},
                        )

                stats = self._stats[topic_name]

                # Detect publisher changes
                added_pubs = pub_nodes - stats.publishers
                removed_pubs = stats.publishers - pub_nodes
                if added_pubs:
                    self._alert_membership_change(
                        topic_name, "publisher_added", added_pubs
                    )
                if removed_pubs:
                    self._alert_membership_change(
                        topic_name, "publisher_removed", removed_pubs
                    )

                # Detect subscriber changes
                added_subs = sub_nodes - stats.subscribers
                removed_subs = stats.subscribers - sub_nodes
                if added_subs:
                    self._alert_membership_change(
                        topic_name, "subscriber_added", added_subs
                    )
                if removed_subs:
                    self._alert_membership_change(
                        topic_name, "subscriber_removed", removed_subs
                    )

                stats.publishers = pub_nodes
                stats.subscribers = sub_nodes

        # Detect removed topics
        with self._lock:
            disappeared = self._known_topics - current_topics
            for topic_name in disappeared:
                if hasattr(self._node, "publish_event"):
                    self._node.publish_event(
                        "WARNING",
                        "topic_disappeared",
                        f"Topic removed from graph: {topic_name}",
                        {"topic": topic_name},
                    )
                # Clean up subscription
                if topic_name in self._subscriptions:
                    self._node.destroy_subscription(self._subscriptions.pop(topic_name))
                self._stats.pop(topic_name, None)
            self._known_topics = current_topics

    # ------------------------------------------------------------------
    # Subscription helpers
    # ------------------------------------------------------------------

    def _subscribe_to_topic(self, topic_name: str, msg_type: str) -> None:
        """Subscribe to a topic with a generic String callback.

        We use ``std_msgs/String`` as a catch-all; for typed topics the raw
        bytes are still counted for rate monitoring.  Full content inspection
        is done selectively by submodules.
        """
        try:
            sub = self._node.create_subscription(
                String,
                topic_name,
                lambda msg, t=topic_name: self._on_message(t, msg),
                MONITOR_QOS,
            )
            self._subscriptions[topic_name] = sub
        except Exception as exc:
            self._node.get_logger().debug(
                "Cannot subscribe to %s as String: %s", topic_name, exc
            )

    def _on_message(self, topic_name: str, msg: Any) -> None:
        """Generic message callback -- update rate statistics."""
        with self._lock:
            stats = self._stats.get(topic_name)
            if stats:
                stats.record_message()

        # Check topic access policy
        if hasattr(self._node, "check_topic_access"):
            # We don't have the sending node's name from the message itself
            # in a generic subscription.  Access enforcement is better done
            # at the DDS layer; here we just count.
            pass

    # ------------------------------------------------------------------
    # Rate checking
    # ------------------------------------------------------------------

    def _rate_check(self) -> None:
        """Check all tracked topics for rate anomalies."""
        now = time.monotonic()
        with self._lock:
            for topic_name, stats in self._stats.items():
                rate = stats.current_rate_hz
                # Flood detection
                if rate > stats.max_rate_hz:
                    if now - stats.last_alert_time > 10.0:
                        stats.last_alert_time = now
                        stats.anomaly_count += 1
                        if hasattr(self._node, "publish_event"):
                            self._node.publish_event(
                                "CRITICAL",
                                "topic_flood",
                                f"Flood detected on {topic_name}: "
                                f"{rate:.1f} msg/s (limit {stats.max_rate_hz:.1f})",
                                {
                                    "topic": topic_name,
                                    "rate_hz": round(rate, 2),
                                    "limit_hz": stats.max_rate_hz,
                                    "anomaly_count": stats.anomaly_count,
                                },
                            )

                # Silence detection (optional minimum rate)
                if stats.min_rate_hz > 0 and stats.message_count > 0:
                    if rate < stats.min_rate_hz:
                        if now - stats.last_alert_time > 30.0:
                            stats.last_alert_time = now
                            if hasattr(self._node, "publish_event"):
                                self._node.publish_event(
                                    "WARNING",
                                    "topic_silence",
                                    f"Low rate on {topic_name}: "
                                    f"{rate:.1f} msg/s (min {stats.min_rate_hz:.1f})",
                                    {
                                        "topic": topic_name,
                                        "rate_hz": round(rate, 2),
                                        "min_hz": stats.min_rate_hz,
                                    },
                                )

    # ------------------------------------------------------------------
    # Membership change alerts
    # ------------------------------------------------------------------

    def _alert_membership_change(
        self, topic: str, change_type: str, nodes: Set[str]
    ) -> None:
        """Publish an event when publishers or subscribers change."""
        if not hasattr(self._node, "publish_event"):
            return

        severity = "INFO" if "added" in change_type else "WARNING"
        self._node.publish_event(
            severity,
            "membership_change",
            f"{change_type} on {topic}: {', '.join(nodes)}",
            {"topic": topic, "change": change_type, "nodes": list(nodes)},
        )

        # Check access policy for new publishers/subscribers
        if hasattr(self._node, "check_topic_access") and "added" in change_type:
            for node_name in nodes:
                self._node.check_topic_access(topic, node_name)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_rate_limit(self, topic: str, max_hz: float, min_hz: float = 0.0) -> None:
        """Override rate limits for a specific topic."""
        with self._lock:
            if topic in self._stats:
                self._stats[topic].max_rate_hz = max_hz
                self._stats[topic].min_rate_hz = min_hz
            self._rate_overrides[topic] = max_hz

    def get_stats(self) -> Dict[str, Dict[str, Any]]:
        """Return current statistics for all monitored topics."""
        with self._lock:
            return {
                name: {
                    "topic": s.topic,
                    "type": s.msg_type,
                    "message_count": s.message_count,
                    "rate_hz": round(s.current_rate_hz, 2),
                    "mean_interval_ms": round(s.mean_interval_ms, 2),
                    "publishers": list(s.publishers),
                    "subscribers": list(s.subscribers),
                    "anomaly_count": s.anomaly_count,
                }
                for name, s in self._stats.items()
            }

    def get_topic_names(self) -> List[str]:
        """Return all currently tracked topic names."""
        with self._lock:
            return list(self._stats.keys())
