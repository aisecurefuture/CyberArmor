"""
AIShields Protect - ROS2 Sensor Data Integrity Monitor
Detects anomalies, replay attacks, stale data, and calibration drift.
"""

import time
import math
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Deque
from collections import deque
from enum import Enum

logger = logging.getLogger("aishields.ros.sensor_integrity")


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class SensorConfig:
    sensor_id: str
    sensor_type: str           # lidar, imu, camera, gps, encoder, force_torque
    min_value: float = -1e6
    max_value: float = 1e6
    max_rate_of_change: float = 1000.0     # max delta per second
    max_staleness_ms: float = 500.0        # max age before stale alert
    expected_frequency_hz: float = 30.0
    frequency_tolerance: float = 0.2       # 20% tolerance
    anomaly_std_threshold: float = 4.0     # standard deviations for anomaly
    replay_window_size: int = 50           # samples to check for replay


@dataclass
class IntegrityAlert:
    severity: AlertSeverity
    sensor_id: str
    alert_type: str
    message: str
    timestamp: float = field(default_factory=time.time)
    details: dict = field(default_factory=dict)


class SensorIntegrityMonitor:
    def __init__(self):
        self.sensors: Dict[str, SensorConfig] = {}
        self._history: Dict[str, Deque[Tuple[float, float]]] = {}
        self._hash_history: Dict[str, Deque[str]] = {}
        self._frequency_tracker: Dict[str, Deque[float]] = {}
        self._alerts: List[IntegrityAlert] = []
        self._stats: Dict[str, dict] = {}
        self._calibration_baseline: Dict[str, dict] = {}

    def register_sensor(self, config: SensorConfig):
        self.sensors[config.sensor_id] = config
        self._history[config.sensor_id] = deque(maxlen=1000)
        self._hash_history[config.sensor_id] = deque(maxlen=config.replay_window_size * 2)
        self._frequency_tracker[config.sensor_id] = deque(maxlen=200)
        self._stats[config.sensor_id] = {
            "count": 0, "sum": 0.0, "sum_sq": 0.0,
            "min": float("inf"), "max": float("-inf"),
        }
        logger.info(f"Registered sensor: {config.sensor_id} ({config.sensor_type})")

    def validate_reading(
        self, sensor_id: str, value: float, timestamp: Optional[float] = None
    ) -> List[IntegrityAlert]:
        """Validate a single sensor reading and return any alerts."""
        if sensor_id not in self.sensors:
            return [IntegrityAlert(
                AlertSeverity.WARNING, sensor_id, "unknown_sensor",
                f"Reading from unregistered sensor: {sensor_id}",
            )]

        config = self.sensors[sensor_id]
        ts = timestamp or time.time()
        alerts: List[IntegrityAlert] = []

        # Range validation
        range_alert = self._check_range(config, value, ts)
        if range_alert:
            alerts.append(range_alert)

        # Rate of change
        roc_alert = self._check_rate_of_change(config, value, ts)
        if roc_alert:
            alerts.append(roc_alert)

        # Statistical anomaly
        anomaly_alert = self._check_anomaly(config, value, ts)
        if anomaly_alert:
            alerts.append(anomaly_alert)

        # Replay detection
        replay_alert = self._check_replay(config, value, ts)
        if replay_alert:
            alerts.append(replay_alert)

        # Frequency monitoring
        freq_alert = self._check_frequency(config, ts)
        if freq_alert:
            alerts.append(freq_alert)

        # Calibration drift
        drift_alert = self._check_calibration_drift(config, value, ts)
        if drift_alert:
            alerts.append(drift_alert)

        # Update history and stats
        self._history[sensor_id].append((ts, value))
        self._frequency_tracker[sensor_id].append(ts)
        stats = self._stats[sensor_id]
        stats["count"] += 1
        stats["sum"] += value
        stats["sum_sq"] += value * value
        stats["min"] = min(stats["min"], value)
        stats["max"] = max(stats["max"], value)

        # Update hash history for replay detection
        data_hash = hashlib.sha256(f"{value:.10f}".encode()).hexdigest()[:16]
        self._hash_history[sensor_id].append(data_hash)

        self._alerts.extend(alerts)
        return alerts

    def check_staleness(self) -> List[IntegrityAlert]:
        """Check all sensors for stale data."""
        alerts = []
        now = time.time()
        for sensor_id, config in self.sensors.items():
            history = self._history.get(sensor_id, deque())
            if not history:
                continue
            last_ts = history[-1][0]
            age_ms = (now - last_ts) * 1000
            if age_ms > config.max_staleness_ms:
                alert = IntegrityAlert(
                    AlertSeverity.WARNING, sensor_id, "stale_data",
                    f"Sensor {sensor_id} data is {age_ms:.0f}ms old (limit: {config.max_staleness_ms}ms)",
                    details={"age_ms": age_ms, "limit_ms": config.max_staleness_ms},
                )
                alerts.append(alert)
        return alerts

    def cross_validate(
        self, sensor_pairs: List[Tuple[str, str]], max_divergence: float = 0.1
    ) -> List[IntegrityAlert]:
        """Cross-validate readings from redundant sensor pairs."""
        alerts = []
        for s1_id, s2_id in sensor_pairs:
            h1 = self._history.get(s1_id, deque())
            h2 = self._history.get(s2_id, deque())
            if not h1 or not h2:
                continue
            v1 = h1[-1][1]
            v2 = h2[-1][1]
            divergence = abs(v1 - v2)
            max_val = max(abs(v1), abs(v2), 1e-10)
            relative_div = divergence / max_val

            if relative_div > max_divergence:
                alert = IntegrityAlert(
                    AlertSeverity.WARNING, f"{s1_id}+{s2_id}", "cross_validation_fail",
                    f"Sensors {s1_id} ({v1:.4f}) and {s2_id} ({v2:.4f}) diverge by {relative_div:.1%}",
                    details={"sensor_1": s1_id, "value_1": v1, "sensor_2": s2_id, "value_2": v2},
                )
                alerts.append(alert)
        return alerts

    def set_calibration_baseline(self, sensor_id: str, mean: float, std: float):
        self._calibration_baseline[sensor_id] = {"mean": mean, "std": std, "set_at": time.time()}

    def _check_range(self, config: SensorConfig, value: float, ts: float) -> Optional[IntegrityAlert]:
        if value < config.min_value or value > config.max_value:
            return IntegrityAlert(
                AlertSeverity.CRITICAL, config.sensor_id, "out_of_range",
                f"Sensor {config.sensor_id} value {value:.4f} outside range [{config.min_value}, {config.max_value}]",
                ts, {"value": value, "min": config.min_value, "max": config.max_value},
            )
        return None

    def _check_rate_of_change(self, config: SensorConfig, value: float, ts: float) -> Optional[IntegrityAlert]:
        history = self._history.get(config.sensor_id, deque())
        if not history:
            return None
        last_ts, last_val = history[-1]
        dt = ts - last_ts
        if dt <= 0:
            return None
        rate = abs(value - last_val) / dt
        if rate > config.max_rate_of_change:
            return IntegrityAlert(
                AlertSeverity.WARNING, config.sensor_id, "excessive_rate_of_change",
                f"Sensor {config.sensor_id} rate of change {rate:.2f}/s exceeds limit {config.max_rate_of_change}/s",
                ts, {"rate": rate, "limit": config.max_rate_of_change},
            )
        return None

    def _check_anomaly(self, config: SensorConfig, value: float, ts: float) -> Optional[IntegrityAlert]:
        stats = self._stats.get(config.sensor_id, {})
        count = stats.get("count", 0)
        if count < 30:
            return None
        mean = stats["sum"] / count
        variance = (stats["sum_sq"] / count) - (mean * mean)
        std = math.sqrt(max(variance, 1e-10))
        z_score = abs(value - mean) / std
        if z_score > config.anomaly_std_threshold:
            return IntegrityAlert(
                AlertSeverity.WARNING, config.sensor_id, "statistical_anomaly",
                f"Sensor {config.sensor_id} value {value:.4f} is {z_score:.1f} std devs from mean {mean:.4f}",
                ts, {"value": value, "mean": mean, "std": std, "z_score": z_score},
            )
        return None

    def _check_replay(self, config: SensorConfig, value: float, ts: float) -> Optional[IntegrityAlert]:
        """Detect repeated identical sequences (replay attack indicator)."""
        hashes = self._hash_history.get(config.sensor_id, deque())
        if len(hashes) < config.replay_window_size:
            return None

        current_hash = hashlib.sha256(f"{value:.10f}".encode()).hexdigest()[:16]
        recent = list(hashes)[-config.replay_window_size:]
        recent_str = "|".join(recent)
        older = list(hashes)[:-config.replay_window_size]
        if len(older) >= config.replay_window_size:
            older_str = "|".join(older[-config.replay_window_size:])
            if recent_str == older_str:
                return IntegrityAlert(
                    AlertSeverity.CRITICAL, config.sensor_id, "replay_attack",
                    f"Sensor {config.sensor_id}: repeated identical sequence detected (possible replay attack)",
                    ts, {"window_size": config.replay_window_size},
                )
        return None

    def _check_frequency(self, config: SensorConfig, ts: float) -> Optional[IntegrityAlert]:
        tracker = self._frequency_tracker.get(config.sensor_id, deque())
        if len(tracker) < 10:
            return None
        window = list(tracker)[-50:]
        if len(window) < 2:
            return None
        duration = window[-1] - window[0]
        if duration <= 0:
            return None
        actual_hz = (len(window) - 1) / duration
        expected = config.expected_frequency_hz
        tolerance = config.frequency_tolerance
        if abs(actual_hz - expected) / max(expected, 1) > tolerance:
            return IntegrityAlert(
                AlertSeverity.WARNING, config.sensor_id, "frequency_anomaly",
                f"Sensor {config.sensor_id} frequency {actual_hz:.1f}Hz deviates from expected {expected}Hz",
                ts, {"actual_hz": actual_hz, "expected_hz": expected},
            )
        return None

    def _check_calibration_drift(self, config: SensorConfig, value: float, ts: float) -> Optional[IntegrityAlert]:
        baseline = self._calibration_baseline.get(config.sensor_id)
        if not baseline:
            return None
        stats = self._stats[config.sensor_id]
        if stats["count"] < 100:
            return None
        current_mean = stats["sum"] / stats["count"]
        baseline_mean = baseline["mean"]
        drift = abs(current_mean - baseline_mean)
        threshold = 3 * baseline["std"]
        if drift > threshold:
            return IntegrityAlert(
                AlertSeverity.WARNING, config.sensor_id, "calibration_drift",
                f"Sensor {config.sensor_id} mean drifted from {baseline_mean:.4f} to {current_mean:.4f}",
                ts, {"baseline_mean": baseline_mean, "current_mean": current_mean, "drift": drift},
            )
        return None

    def get_alerts(self, limit: int = 100) -> List[IntegrityAlert]:
        return self._alerts[-limit:]

    def get_sensor_stats(self, sensor_id: str) -> Optional[dict]:
        stats = self._stats.get(sensor_id)
        if not stats or stats["count"] == 0:
            return None
        count = stats["count"]
        mean = stats["sum"] / count
        variance = (stats["sum_sq"] / count) - (mean * mean)
        return {
            "sensor_id": sensor_id,
            "count": count,
            "mean": mean,
            "std": math.sqrt(max(variance, 0)),
            "min": stats["min"],
            "max": stats["max"],
        }
