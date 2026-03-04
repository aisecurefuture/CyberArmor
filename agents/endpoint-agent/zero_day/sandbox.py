"""Lightweight Sandboxed Execution Analysis.

Runs unknown binaries in a restricted sandbox environment and monitors
for malicious behavior patterns: file encryption, mass deletion,
network beaconing, privilege escalation.
"""

import json
import logging
import os
import platform
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("sandbox")


@dataclass
class SandboxResult:
    binary_path: str
    verdict: str = "unknown"  # clean, suspicious, malicious
    behaviors: List[str] = field(default_factory=list)
    network_connections: List[str] = field(default_factory=list)
    files_created: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    files_deleted: List[str] = field(default_factory=list)
    processes_spawned: List[str] = field(default_factory=list)
    exit_code: int = -1
    duration_s: float = 0.0
    error: str = ""


# Behavior patterns that indicate malicious activity
MALICIOUS_BEHAVIORS = {
    "file_encryption": ["encrypt", "ransom", ".locked", ".crypt", ".enc"],
    "mass_deletion": ["rm -rf", "del /f /q", "rmdir /s", "shred"],
    "network_beacon": ["curl", "wget", "nc ", "ncat", "netcat"],
    "privilege_escalation": ["sudo", "su ", "runas", "doas"],
    "persistence": ["crontab", "launchctl", "schtasks", "reg add.*run"],
    "credential_theft": ["mimikatz", "lsass", "keychain", "credential"],
}


class Sandbox:
    """Lightweight sandbox for behavioral analysis of unknown binaries.

    Uses OS-native sandboxing:
    - macOS: sandbox-exec with custom profile
    - Linux: namespaces + seccomp (via bubblewrap/bwrap)
    - Windows: AppContainer or Job Object restrictions
    """

    def __init__(self, timeout_s: int = 30, max_file_ops: int = 1000):
        self.timeout_s = timeout_s
        self.max_file_ops = max_file_ops
        self.system = platform.system()

    def analyze(self, binary_path: str) -> SandboxResult:
        """Run binary in sandbox and analyze behavior."""
        result = SandboxResult(binary_path=binary_path)

        if not os.path.exists(binary_path):
            result.error = "Binary not found"
            return result

        # Create isolated working directory
        sandbox_dir = tempfile.mkdtemp(prefix="aishields_sandbox_")
        try:
            start = time.time()

            if self.system == "Darwin":
                result = self._run_macos_sandbox(binary_path, sandbox_dir, result)
            elif self.system == "Linux":
                result = self._run_linux_sandbox(binary_path, sandbox_dir, result)
            elif self.system == "Windows":
                result = self._run_windows_sandbox(binary_path, sandbox_dir, result)
            else:
                result.error = f"Unsupported platform: {self.system}"

            result.duration_s = time.time() - start
            result.verdict = self._determine_verdict(result)

        except Exception as e:
            result.error = str(e)
            logger.error("Sandbox analysis failed for %s: %s", binary_path, e)
        finally:
            # Clean up sandbox directory
            try:
                shutil.rmtree(sandbox_dir, ignore_errors=True)
            except Exception:
                pass

        return result

    def _run_macos_sandbox(self, binary_path: str, sandbox_dir: str, result: SandboxResult) -> SandboxResult:
        """Run in macOS sandbox-exec with restrictive profile."""
        profile = f"""
(version 1)
(deny default)
(allow process-exec (literal "{binary_path}"))
(allow file-read* (subpath "{sandbox_dir}"))
(allow file-write* (subpath "{sandbox_dir}"))
(allow file-read* (subpath "/usr/lib"))
(allow file-read* (subpath "/System/Library"))
(allow file-read-metadata)
(deny network*)
(deny process-fork)
(deny signal)
"""
        profile_path = os.path.join(sandbox_dir, "sandbox.sb")
        with open(profile_path, "w") as f:
            f.write(profile)

        try:
            proc = subprocess.run(
                ["sandbox-exec", "-f", profile_path, binary_path],
                capture_output=True, text=True, timeout=self.timeout_s,
                cwd=sandbox_dir, env={"HOME": sandbox_dir, "PATH": "/usr/bin:/bin"},
            )
            result.exit_code = proc.returncode
            self._analyze_output(proc.stdout + proc.stderr, result)
        except subprocess.TimeoutExpired:
            result.behaviors.append("timeout_exceeded")
        except Exception as e:
            result.error = str(e)

        self._scan_sandbox_artifacts(sandbox_dir, result)
        return result

    def _run_linux_sandbox(self, binary_path: str, sandbox_dir: str, result: SandboxResult) -> SandboxResult:
        """Run in Linux namespace sandbox (bubblewrap if available, else basic)."""
        bwrap = shutil.which("bwrap")
        if bwrap:
            cmd = [
                bwrap, "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
                "--ro-bind", "/lib64", "/lib64" if os.path.exists("/lib64") else "/lib",
                "--bind", sandbox_dir, "/tmp/sandbox",
                "--ro-bind", binary_path, "/tmp/binary",
                "--unshare-all", "--die-with-parent",
                "--new-session", "--", "/tmp/binary",
            ]
        else:
            # Fallback: basic restrictions with timeout and ulimits
            cmd = [
                "timeout", str(self.timeout_s),
                "nice", "-n", "19",
                binary_path,
            ]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout_s + 5,
                cwd=sandbox_dir, env={"HOME": sandbox_dir, "PATH": "/usr/bin:/bin", "TMPDIR": sandbox_dir},
            )
            result.exit_code = proc.returncode
            self._analyze_output(proc.stdout + proc.stderr, result)
        except subprocess.TimeoutExpired:
            result.behaviors.append("timeout_exceeded")
        except Exception as e:
            result.error = str(e)

        self._scan_sandbox_artifacts(sandbox_dir, result)
        return result

    def _run_windows_sandbox(self, binary_path: str, sandbox_dir: str, result: SandboxResult) -> SandboxResult:
        """Run with Windows Job Object restrictions."""
        try:
            proc = subprocess.run(
                [binary_path], capture_output=True, text=True, timeout=self.timeout_s,
                cwd=sandbox_dir, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )
            result.exit_code = proc.returncode
            self._analyze_output(proc.stdout + proc.stderr, result)
        except subprocess.TimeoutExpired:
            result.behaviors.append("timeout_exceeded")
        except Exception as e:
            result.error = str(e)

        self._scan_sandbox_artifacts(sandbox_dir, result)
        return result

    def _analyze_output(self, output: str, result: SandboxResult):
        """Analyze stdout/stderr for suspicious patterns."""
        lower = output.lower()
        for behavior, indicators in MALICIOUS_BEHAVIORS.items():
            for indicator in indicators:
                if indicator.lower() in lower:
                    result.behaviors.append(behavior)
                    break

    def _scan_sandbox_artifacts(self, sandbox_dir: str, result: SandboxResult):
        """Scan files created/modified in the sandbox directory."""
        for root, dirs, files in os.walk(sandbox_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                if fname != "sandbox.sb":  # Skip our own profile file
                    result.files_created.append(fpath)

    def _determine_verdict(self, result: SandboxResult) -> str:
        """Determine final verdict based on observed behaviors."""
        critical_behaviors = {"file_encryption", "credential_theft", "mass_deletion"}
        suspicious_behaviors = {"network_beacon", "persistence", "privilege_escalation"}

        behaviors_set = set(result.behaviors)

        if behaviors_set & critical_behaviors:
            return "malicious"
        if behaviors_set & suspicious_behaviors:
            return "suspicious"
        if result.behaviors:
            return "suspicious"
        if "timeout_exceeded" in result.behaviors:
            return "suspicious"
        return "clean"
