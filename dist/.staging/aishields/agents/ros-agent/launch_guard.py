"""
AIShields Protect - ROS2 Launch Guard
Validates launch files and monitors node launches for security policy compliance.
"""

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import logging
import yaml

logger = logging.getLogger("aishields.ros.launch_guard")

UNSAFE_PARAM_PATTERNS = [
    re.compile(r"(?:bash|sh|zsh|cmd|powershell)\s+-c\s+", re.I),
    re.compile(r"(?:rm\s+-rf|mkfs|dd\s+if=|chmod\s+777|curl.*\|.*sh)", re.I),
    re.compile(r"https?://(?!localhost|127\.0\.0\.1)", re.I),
    re.compile(r"/(?:tmp|dev/shm|var/tmp)/", re.I),
    re.compile(r"(?:eval|exec|system|popen|subprocess)\s*\(", re.I),
]

SUSPICIOUS_ENV_VARS = {
    "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PATH",
    "HOME", "SHELL", "TERM", "DISPLAY",
}


@dataclass
class LaunchValidation:
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    nodes_declared: List[str] = field(default_factory=list)


@dataclass
class NodePolicy:
    allowed_nodes: Set[str] = field(default_factory=set)
    denied_nodes: Set[str] = field(default_factory=set)
    allowed_packages: Set[str] = field(default_factory=set)
    max_node_count: int = 100
    require_namespace: bool = True
    allowed_namespaces: Set[str] = field(default_factory=set)


class LaunchGuard:
    def __init__(self, policy: Optional[NodePolicy] = None):
        self.policy = policy or NodePolicy()
        self.active_nodes: Dict[str, dict] = {}
        self._launch_history: List[dict] = []

    def validate_launch_file(self, filepath: str) -> LaunchValidation:
        """Validate a ROS2 launch file before execution."""
        result = LaunchValidation(valid=True)

        if not os.path.exists(filepath):
            result.valid = False
            result.errors.append(f"Launch file not found: {filepath}")
            return result

        ext = os.path.splitext(filepath)[1].lower()
        if ext == ".xml":
            return self._validate_xml_launch(filepath, result)
        elif ext in (".yaml", ".yml"):
            return self._validate_yaml_launch(filepath, result)
        elif ext == ".py":
            return self._validate_python_launch(filepath, result)
        else:
            result.warnings.append(f"Unknown launch file format: {ext}")
            return result

    def _validate_xml_launch(self, filepath: str, result: LaunchValidation) -> LaunchValidation:
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
        except ET.ParseError as e:
            result.valid = False
            result.errors.append(f"XML parse error: {e}")
            return result

        for node_elem in root.iter("node"):
            pkg = node_elem.get("pkg", "")
            executable = node_elem.get("exec", node_elem.get("type", ""))
            name = node_elem.get("name", executable)
            namespace = node_elem.get("namespace", "")
            fqn = f"{namespace}/{name}" if namespace else name

            result.nodes_declared.append(fqn)
            self._check_node_policy(fqn, pkg, result)

            # Check parameters for unsafe values
            for param in node_elem.iter("param"):
                param_name = param.get("name", "")
                param_value = param.get("value", param.text or "")
                self._check_param_safety(param_name, param_value, fqn, result)

            # Check remappings
            for remap in node_elem.iter("remap"):
                from_topic = remap.get("from", "")
                to_topic = remap.get("to", "")
                if "/cmd_vel" in to_topic or "/joint_command" in to_topic:
                    result.warnings.append(
                        f"Node {fqn} remaps to actuator topic {to_topic}"
                    )

        # Check for environment variable overrides
        for env_elem in root.iter("env"):
            env_name = env_elem.get("name", "")
            if env_name in SUSPICIOUS_ENV_VARS:
                result.warnings.append(
                    f"Launch file modifies sensitive env var: {env_name}"
                )

        # Check for executable launches (not nodes)
        for exec_elem in root.iter("executable"):
            cmd = exec_elem.get("cmd", "")
            result.warnings.append(f"Launch file executes arbitrary command: {cmd}")
            for pattern in UNSAFE_PARAM_PATTERNS:
                if pattern.search(cmd):
                    result.valid = False
                    result.errors.append(f"Unsafe command execution: {cmd}")

        return result

    def _validate_yaml_launch(self, filepath: str, result: LaunchValidation) -> LaunchValidation:
        try:
            with open(filepath, "r") as f:
                launch_config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            result.valid = False
            result.errors.append(f"YAML parse error: {e}")
            return result

        if not isinstance(launch_config, dict):
            result.valid = False
            result.errors.append("Invalid launch YAML structure")
            return result

        for node_name, node_config in launch_config.get("nodes", {}).items():
            if isinstance(node_config, dict):
                pkg = node_config.get("package", "")
                result.nodes_declared.append(node_name)
                self._check_node_policy(node_name, pkg, result)

                for pname, pval in node_config.get("parameters", {}).items():
                    self._check_param_safety(pname, str(pval), node_name, result)

        return result

    def _validate_python_launch(self, filepath: str, result: LaunchValidation) -> LaunchValidation:
        """Static analysis of Python launch files."""
        try:
            with open(filepath, "r") as f:
                content = f.read()
        except IOError as e:
            result.valid = False
            result.errors.append(f"Cannot read file: {e}")
            return result

        # Detect Node declarations
        node_pattern = re.compile(
            r"Node\s*\(\s*(?:package\s*=\s*['\"](\w+)['\"].*?"
            r"executable\s*=\s*['\"](\w+)['\"]|"
            r"executable\s*=\s*['\"](\w+)['\"].*?"
            r"package\s*=\s*['\"](\w+)['\"])",
            re.DOTALL,
        )
        for match in node_pattern.finditer(content):
            pkg = match.group(1) or match.group(4) or ""
            exe = match.group(2) or match.group(3) or ""
            result.nodes_declared.append(f"{pkg}/{exe}")
            self._check_node_policy(exe, pkg, result)

        # Check for dangerous imports/calls
        dangerous_patterns = [
            (r"import\s+subprocess", "Launch file imports subprocess"),
            (r"os\.system\s*\(", "Launch file uses os.system()"),
            (r"os\.popen\s*\(", "Launch file uses os.popen()"),
            (r"eval\s*\(", "Launch file uses eval()"),
            (r"exec\s*\(", "Launch file uses exec()"),
            (r"__import__\s*\(", "Launch file uses dynamic import"),
        ]
        for pattern, msg in dangerous_patterns:
            if re.search(pattern, content):
                result.warnings.append(msg)

        # Check for shell=True in ExecuteProcess
        if re.search(r"ExecuteProcess.*shell\s*=\s*True", content, re.DOTALL):
            result.valid = False
            result.errors.append("ExecuteProcess with shell=True is a security risk")

        return result

    def _check_node_policy(self, node_name: str, package: str, result: LaunchValidation):
        if self.policy.denied_nodes and node_name in self.policy.denied_nodes:
            result.valid = False
            result.errors.append(f"Node {node_name} is explicitly denied by policy")

        if self.policy.allowed_nodes and node_name not in self.policy.allowed_nodes:
            result.valid = False
            result.errors.append(f"Node {node_name} is not in the allowed nodes list")

        if self.policy.allowed_packages and package and package not in self.policy.allowed_packages:
            result.warnings.append(f"Package {package} is not in the allowed packages list")

    def _check_param_safety(self, name: str, value: str, node: str, result: LaunchValidation):
        for pattern in UNSAFE_PARAM_PATTERNS:
            if pattern.search(value):
                result.valid = False
                result.errors.append(
                    f"Unsafe parameter value for {name} in node {node}: {value[:80]}"
                )
                return

    def on_node_started(self, node_name: str, pid: int, package: str = "", namespace: str = ""):
        """Called when a new ROS2 node starts."""
        fqn = f"{namespace}/{node_name}" if namespace else node_name

        if len(self.active_nodes) >= self.policy.max_node_count:
            logger.warning(
                f"Max node count ({self.policy.max_node_count}) reached, "
                f"new node {fqn} may indicate resource abuse"
            )

        if self.policy.denied_nodes and node_name in self.policy.denied_nodes:
            logger.critical(f"DENIED node launched: {fqn} (PID: {pid})")
            return {"action": "kill", "reason": "denied_by_policy", "node": fqn, "pid": pid}

        self.active_nodes[fqn] = {
            "pid": pid,
            "package": package,
            "namespace": namespace,
            "started_at": __import__("time").time(),
        }

        self._launch_history.append({
            "node": fqn,
            "pid": pid,
            "package": package,
            "timestamp": __import__("time").time(),
        })

        logger.info(f"Node started: {fqn} (PID: {pid}, package: {package})")
        return {"action": "allow", "node": fqn}

    def on_node_stopped(self, node_name: str, namespace: str = ""):
        fqn = f"{namespace}/{node_name}" if namespace else node_name
        self.active_nodes.pop(fqn, None)
        logger.info(f"Node stopped: {fqn}")

    def get_active_nodes(self) -> Dict[str, dict]:
        return dict(self.active_nodes)

    def get_launch_history(self) -> List[dict]:
        return list(self._launch_history[-1000:])
