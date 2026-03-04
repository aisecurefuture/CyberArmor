"""
AIShields Protect - ROS2 Actuator Safety Policy Engine
Enforces velocity, acceleration, force limits, geofencing, and emergency stop.
"""

import time
import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum

logger = logging.getLogger("aishields.ros.actuator_policy")


class PolicyAction(Enum):
    ALLOW = "allow"
    CLAMP = "clamp"
    REJECT = "reject"
    EMERGENCY_STOP = "emergency_stop"


@dataclass
class ActuatorLimits:
    max_linear_velocity: float = 2.0       # m/s
    max_angular_velocity: float = 1.5      # rad/s
    max_linear_acceleration: float = 3.0   # m/s^2
    max_angular_acceleration: float = 2.0  # rad/s^2
    max_force: float = 100.0               # N
    max_torque: float = 50.0               # Nm
    rate_limit_hz: float = 100.0           # Max command frequency


@dataclass
class GeoFence:
    x_min: float = -100.0
    x_max: float = 100.0
    y_min: float = -100.0
    y_max: float = 100.0
    z_min: float = 0.0
    z_max: float = 50.0


@dataclass
class SafetyZone:
    name: str
    center_x: float
    center_y: float
    radius: float
    action: PolicyAction = PolicyAction.REJECT
    description: str = ""


@dataclass
class CommandRecord:
    timestamp: float
    linear_x: float = 0.0
    linear_y: float = 0.0
    linear_z: float = 0.0
    angular_x: float = 0.0
    angular_y: float = 0.0
    angular_z: float = 0.0
    force: float = 0.0
    torque: float = 0.0


@dataclass
class PolicyResult:
    action: PolicyAction
    original_command: dict
    modified_command: Optional[dict] = None
    violations: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class ActuatorPolicy:
    def __init__(
        self,
        limits: Optional[ActuatorLimits] = None,
        geofence: Optional[GeoFence] = None,
        safety_zones: Optional[List[SafetyZone]] = None,
    ):
        self.limits = limits or ActuatorLimits()
        self.geofence = geofence or GeoFence()
        self.safety_zones = safety_zones or []
        self.emergency_stopped = False
        self._command_history: Dict[str, List[CommandRecord]] = {}
        self._audit_log: List[dict] = []
        self._current_position: Optional[Tuple[float, float, float]] = None

    def emergency_stop(self, reason: str = "manual"):
        """Activate emergency stop - rejects ALL actuator commands."""
        self.emergency_stopped = True
        logger.critical(f"EMERGENCY STOP activated: {reason}")
        self._audit("emergency_stop", {"reason": reason})

    def release_emergency_stop(self):
        """Release emergency stop."""
        self.emergency_stopped = False
        logger.info("Emergency stop released")
        self._audit("emergency_stop_released", {})

    def update_position(self, x: float, y: float, z: float):
        """Update current robot position for geofence checks."""
        self._current_position = (x, y, z)

    def evaluate_velocity_command(
        self, actuator_id: str, linear_x: float, linear_y: float, linear_z: float,
        angular_x: float, angular_y: float, angular_z: float,
    ) -> PolicyResult:
        """Evaluate a velocity command against safety policies."""
        cmd = {
            "linear_x": linear_x, "linear_y": linear_y, "linear_z": linear_z,
            "angular_x": angular_x, "angular_y": angular_y, "angular_z": angular_z,
        }

        if self.emergency_stopped:
            return PolicyResult(
                action=PolicyAction.EMERGENCY_STOP,
                original_command=cmd,
                modified_command=self._zero_command(),
                violations=["Emergency stop is active"],
            )

        violations = []
        modified = dict(cmd)

        # Linear velocity check
        linear_speed = math.sqrt(linear_x**2 + linear_y**2 + linear_z**2)
        if linear_speed > self.limits.max_linear_velocity:
            violations.append(
                f"Linear velocity {linear_speed:.2f} exceeds limit {self.limits.max_linear_velocity}"
            )
            scale = self.limits.max_linear_velocity / linear_speed
            modified["linear_x"] *= scale
            modified["linear_y"] *= scale
            modified["linear_z"] *= scale

        # Angular velocity check
        angular_speed = math.sqrt(angular_x**2 + angular_y**2 + angular_z**2)
        if angular_speed > self.limits.max_angular_velocity:
            violations.append(
                f"Angular velocity {angular_speed:.2f} exceeds limit {self.limits.max_angular_velocity}"
            )
            scale = self.limits.max_angular_velocity / angular_speed
            modified["angular_x"] *= scale
            modified["angular_y"] *= scale
            modified["angular_z"] *= scale

        # Acceleration check
        accel_violation = self._check_acceleration(actuator_id, modified)
        if accel_violation:
            violations.append(accel_violation)

        # Rate limiting
        rate_violation = self._check_rate_limit(actuator_id)
        if rate_violation:
            violations.append(rate_violation)
            return PolicyResult(
                action=PolicyAction.REJECT, original_command=cmd, violations=violations,
            )

        # Geofence check
        geo_violation = self._check_geofence()
        if geo_violation:
            violations.append(geo_violation)
            return PolicyResult(
                action=PolicyAction.REJECT, original_command=cmd,
                modified_command=self._zero_command(), violations=violations,
            )

        # Safety zone check
        zone_violation, zone_action = self._check_safety_zones()
        if zone_violation:
            violations.append(zone_violation)
            if zone_action == PolicyAction.EMERGENCY_STOP:
                self.emergency_stop(reason=zone_violation)
                return PolicyResult(
                    action=PolicyAction.EMERGENCY_STOP, original_command=cmd,
                    modified_command=self._zero_command(), violations=violations,
                )
            elif zone_action == PolicyAction.REJECT:
                return PolicyResult(
                    action=PolicyAction.REJECT, original_command=cmd, violations=violations,
                )

        # Record command
        self._record_command(actuator_id, modified)

        action = PolicyAction.CLAMP if violations else PolicyAction.ALLOW
        self._audit("velocity_command", {
            "actuator": actuator_id, "action": action.value,
            "violations": violations, "command": modified,
        })

        return PolicyResult(
            action=action, original_command=cmd,
            modified_command=modified if violations else None,
            violations=violations,
        )

    def evaluate_force_command(
        self, actuator_id: str, force: float, torque: float,
    ) -> PolicyResult:
        cmd = {"force": force, "torque": torque}

        if self.emergency_stopped:
            return PolicyResult(
                action=PolicyAction.EMERGENCY_STOP, original_command=cmd,
                modified_command={"force": 0.0, "torque": 0.0},
                violations=["Emergency stop is active"],
            )

        violations = []
        modified = dict(cmd)

        if abs(force) > self.limits.max_force:
            violations.append(f"Force {force:.2f}N exceeds limit {self.limits.max_force}N")
            modified["force"] = math.copysign(self.limits.max_force, force)

        if abs(torque) > self.limits.max_torque:
            violations.append(f"Torque {torque:.2f}Nm exceeds limit {self.limits.max_torque}Nm")
            modified["torque"] = math.copysign(self.limits.max_torque, torque)

        action = PolicyAction.CLAMP if violations else PolicyAction.ALLOW
        return PolicyResult(
            action=action, original_command=cmd,
            modified_command=modified if violations else None,
            violations=violations,
        )

    def _check_acceleration(self, actuator_id: str, cmd: dict) -> Optional[str]:
        history = self._command_history.get(actuator_id, [])
        if not history:
            return None

        last = history[-1]
        dt = time.time() - last.timestamp
        if dt <= 0 or dt > 1.0:
            return None

        dv_linear = math.sqrt(
            (cmd["linear_x"] - last.linear_x) ** 2
            + (cmd["linear_y"] - last.linear_y) ** 2
            + (cmd["linear_z"] - last.linear_z) ** 2
        )
        accel = dv_linear / dt
        if accel > self.limits.max_linear_acceleration:
            return f"Linear acceleration {accel:.2f} m/s^2 exceeds limit {self.limits.max_linear_acceleration}"

        dv_angular = math.sqrt(
            (cmd["angular_x"] - last.angular_x) ** 2
            + (cmd["angular_y"] - last.angular_y) ** 2
            + (cmd["angular_z"] - last.angular_z) ** 2
        )
        angular_accel = dv_angular / dt
        if angular_accel > self.limits.max_angular_acceleration:
            return f"Angular acceleration {angular_accel:.2f} rad/s^2 exceeds limit {self.limits.max_angular_acceleration}"

        return None

    def _check_rate_limit(self, actuator_id: str) -> Optional[str]:
        history = self._command_history.get(actuator_id, [])
        if not history:
            return None
        min_interval = 1.0 / self.limits.rate_limit_hz
        dt = time.time() - history[-1].timestamp
        if dt < min_interval:
            return f"Command rate too high ({1.0/max(dt,0.001):.0f} Hz > {self.limits.rate_limit_hz} Hz)"
        return None

    def _check_geofence(self) -> Optional[str]:
        if self._current_position is None:
            return None
        x, y, z = self._current_position
        gf = self.geofence
        if not (gf.x_min <= x <= gf.x_max and gf.y_min <= y <= gf.y_max and gf.z_min <= z <= gf.z_max):
            return f"Position ({x:.1f}, {y:.1f}, {z:.1f}) outside geofence"
        return None

    def _check_safety_zones(self) -> Tuple[Optional[str], Optional[PolicyAction]]:
        if self._current_position is None:
            return None, None
        x, y, _ = self._current_position
        for zone in self.safety_zones:
            dist = math.sqrt((x - zone.center_x) ** 2 + (y - zone.center_y) ** 2)
            if dist < zone.radius:
                return (
                    f"Position inside safety zone '{zone.name}' ({zone.description})",
                    zone.action,
                )
        return None, None

    def _record_command(self, actuator_id: str, cmd: dict):
        record = CommandRecord(
            timestamp=time.time(),
            linear_x=cmd.get("linear_x", 0),
            linear_y=cmd.get("linear_y", 0),
            linear_z=cmd.get("linear_z", 0),
            angular_x=cmd.get("angular_x", 0),
            angular_y=cmd.get("angular_y", 0),
            angular_z=cmd.get("angular_z", 0),
        )
        if actuator_id not in self._command_history:
            self._command_history[actuator_id] = []
        self._command_history[actuator_id].append(record)
        # Keep last 1000 commands per actuator
        self._command_history[actuator_id] = self._command_history[actuator_id][-1000:]

    def _zero_command(self) -> dict:
        return {
            "linear_x": 0, "linear_y": 0, "linear_z": 0,
            "angular_x": 0, "angular_y": 0, "angular_z": 0,
        }

    def _audit(self, event: str, details: dict):
        entry = {"event": event, "timestamp": time.time(), **details}
        self._audit_log.append(entry)
        self._audit_log = self._audit_log[-10000:]

    def get_audit_log(self) -> List[dict]:
        return list(self._audit_log)
