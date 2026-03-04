"""Linux Platform-Specific Security Hooks.

Provides Linux-native integration for:
- eBPF-based process/file/network monitoring (via bcc/bpftrace)
- SELinux / AppArmor policy status
- Auditd integration
- Seccomp profile management
- Namespace isolation (bubblewrap/firejail)
- Systemd service/timer persistence detection
- LUKS disk encryption status
- Package signature verification (dpkg/rpm)
"""

import json
import logging
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("endpoint.platform.linux")


@dataclass
class LinuxSecurityState:
    """Snapshot of Linux security posture."""
    os_version: str = ""
    distro: str = ""
    kernel_version: str = ""
    selinux_status: str = "disabled"  # enforcing, permissive, disabled
    apparmor_status: str = "disabled"  # enforced, complain, disabled
    seccomp_available: bool = False
    firewall_active: bool = False
    firewall_type: str = ""  # iptables, nftables, firewalld, ufw
    disk_encryption: bool = False
    secure_boot: bool = False
    bpf_available: bool = False
    auditd_active: bool = False
    unattended_upgrades: bool = False


@dataclass
class SystemdPersistence:
    """Detected systemd persistence entry."""
    unit_name: str
    unit_type: str  # service, timer, path
    file_path: str
    exec_start: str = ""
    enabled: bool = False
    active: bool = False
    suspicious: bool = False
    reason: str = ""


@dataclass
class CronPersistence:
    """Detected cron job entry."""
    user: str
    schedule: str
    command: str
    file_path: str
    suspicious: bool = False
    reason: str = ""


class LinuxPlatform:
    """Linux-specific security monitoring and enforcement."""

    PERSISTENCE_SYSTEMD_DIRS = [
        Path("/etc/systemd/system"),
        Path.home() / ".config" / "systemd" / "user",
        Path("/usr/lib/systemd/system"),
    ]

    CRON_DIRS = [
        Path("/etc/cron.d"),
        Path("/etc/cron.daily"),
        Path("/etc/cron.hourly"),
        Path("/etc/cron.weekly"),
        Path("/etc/cron.monthly"),
        Path("/var/spool/cron/crontabs"),
    ]

    SUSPICIOUS_COMMANDS = [
        "curl.*|.*sh", "wget.*|.*bash", "python -c", "perl -e",
        "nc -e", "ncat -e", "bash -i", "mkfifo", "/dev/tcp/",
        "base64 -d.*|.*sh", "openssl.*s_client",
    ]

    def __init__(self):
        if platform.system() != "Linux":
            logger.warning("LinuxPlatform instantiated on non-Linux system")
        self._kernel = platform.release() if platform.system() == "Linux" else ""

    # ------------------------------------------------------------------
    # Security Posture Assessment
    # ------------------------------------------------------------------

    def get_security_state(self) -> LinuxSecurityState:
        """Gather comprehensive Linux security posture."""
        state = LinuxSecurityState(
            kernel_version=self._kernel,
            os_version=platform.version(),
        )
        state.distro = self._get_distro()
        state.selinux_status = self._check_selinux()
        state.apparmor_status = self._check_apparmor()
        state.seccomp_available = self._check_seccomp()
        state.firewall_active, state.firewall_type = self._check_firewall()
        state.disk_encryption = self._check_luks()
        state.secure_boot = self._check_secure_boot()
        state.bpf_available = self._check_bpf()
        state.auditd_active = self._check_auditd()
        state.unattended_upgrades = self._check_auto_updates()
        return state

    def _run_cmd(self, cmd: List[str], timeout: int = 10) -> Optional[str]:
        """Run a command and return stdout."""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0:
                return r.stdout.strip()
        except Exception as e:
            logger.debug("Command %s failed: %s", cmd, e)
        return None

    def _get_distro(self) -> str:
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except Exception:
            pass
        return "unknown"

    def _check_selinux(self) -> str:
        result = self._run_cmd(["getenforce"])
        if result:
            return result.lower()
        return "disabled"

    def _check_apparmor(self) -> str:
        result = self._run_cmd(["aa-status", "--json"])
        if result:
            try:
                data = json.loads(result)
                profiles = data.get("profiles", {})
                if any(v == "enforce" for v in profiles.values()):
                    return "enforced"
                if any(v == "complain" for v in profiles.values()):
                    return "complain"
            except json.JSONDecodeError:
                pass
        # Fallback check
        if os.path.exists("/sys/kernel/security/apparmor"):
            return "loaded"
        return "disabled"

    def _check_seccomp(self) -> bool:
        try:
            with open("/proc/sys/kernel/seccomp/actions_avail") as f:
                return bool(f.read().strip())
        except Exception:
            pass
        return os.path.exists("/proc/self/status") and "Seccomp" in open("/proc/self/status").read()

    def _check_firewall(self) -> Tuple[bool, str]:
        # Check firewalld
        result = self._run_cmd(["systemctl", "is-active", "firewalld"])
        if result == "active":
            return True, "firewalld"
        # Check UFW
        result = self._run_cmd(["ufw", "status"])
        if result and "active" in result.lower():
            return True, "ufw"
        # Check nftables
        result = self._run_cmd(["nft", "list", "tables"])
        if result and result.strip():
            return True, "nftables"
        # Check iptables
        result = self._run_cmd(["iptables", "-L", "-n"])
        if result and "Chain" in result:
            return True, "iptables"
        return False, ""

    def _check_luks(self) -> bool:
        result = self._run_cmd(["lsblk", "-f", "-J"])
        if result:
            try:
                data = json.loads(result)
                for device in data.get("blockdevices", []):
                    if self._has_luks(device):
                        return True
            except json.JSONDecodeError:
                pass
        return False

    def _has_luks(self, device: dict) -> bool:
        if device.get("fstype") == "crypto_LUKS":
            return True
        for child in device.get("children", []):
            if self._has_luks(child):
                return True
        return False

    def _check_secure_boot(self) -> bool:
        result = self._run_cmd(["mokutil", "--sb-state"])
        if result:
            return "secureboot enabled" in result.lower()
        return False

    def _check_bpf(self) -> bool:
        return (
            os.path.exists("/sys/kernel/btf/vmlinux")
            or shutil.which("bpftool") is not None
        )

    def _check_auditd(self) -> bool:
        result = self._run_cmd(["systemctl", "is-active", "auditd"])
        return result == "active"

    def _check_auto_updates(self) -> bool:
        # Debian/Ubuntu
        if os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades"):
            try:
                with open("/etc/apt/apt.conf.d/20auto-upgrades") as f:
                    content = f.read()
                return 'Unattended-Upgrade "1"' in content
            except Exception:
                pass
        # RHEL/CentOS - dnf-automatic
        result = self._run_cmd(["systemctl", "is-active", "dnf-automatic.timer"])
        return result == "active"

    # ------------------------------------------------------------------
    # Package Signature Verification
    # ------------------------------------------------------------------

    def verify_package_signature(self, package_path: str) -> Tuple[bool, str]:
        """Verify package signature (deb or rpm)."""
        if package_path.endswith(".deb"):
            result = self._run_cmd(["dpkg-sig", "--verify", package_path])
            if result and "GOODSIG" in result:
                return True, result
            return False, result or "verification failed"
        elif package_path.endswith(".rpm"):
            result = self._run_cmd(["rpm", "-K", package_path])
            if result and "pgp" in result.lower() and "ok" in result.lower():
                return True, result
            return False, result or "verification failed"
        return False, "unsupported package format"

    def verify_elf_binary(self, binary_path: str) -> Dict[str, str]:
        """Analyze an ELF binary for security features."""
        info = {"path": binary_path}

        # Check PIE/ASLR
        result = self._run_cmd(["readelf", "-h", binary_path])
        if result:
            info["pie"] = "DYN" in result

        # Check stack canary, NX, RELRO via checksec
        checksec = shutil.which("checksec")
        if checksec:
            result = self._run_cmd([checksec, "--file", binary_path, "--format=json"])
            if result:
                try:
                    data = json.loads(result)
                    file_data = data.get(binary_path, {})
                    info["relro"] = file_data.get("relro", "unknown")
                    info["stack_canary"] = file_data.get("canary", "unknown")
                    info["nx"] = file_data.get("nx", "unknown")
                    info["fortify"] = file_data.get("fortify_source", "unknown")
                except json.JSONDecodeError:
                    pass

        return info

    # ------------------------------------------------------------------
    # Systemd Persistence Detection
    # ------------------------------------------------------------------

    def scan_systemd_persistence(self) -> List[SystemdPersistence]:
        """Scan systemd units for suspicious persistence."""
        results = []
        for unit_dir in self.PERSISTENCE_SYSTEMD_DIRS:
            if not unit_dir.exists():
                continue
            for unit_file in unit_dir.glob("*.service"):
                entry = self._parse_systemd_unit(unit_file, "service")
                if entry:
                    results.append(entry)
            for unit_file in unit_dir.glob("*.timer"):
                entry = self._parse_systemd_unit(unit_file, "timer")
                if entry:
                    results.append(entry)

        return results

    def _parse_systemd_unit(self, unit_path: Path, unit_type: str) -> Optional[SystemdPersistence]:
        """Parse a systemd unit file for persistence info."""
        try:
            content = unit_path.read_text()
            entry = SystemdPersistence(
                unit_name=unit_path.name,
                unit_type=unit_type,
                file_path=str(unit_path),
            )

            # Extract ExecStart
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("ExecStart="):
                    entry.exec_start = line.split("=", 1)[1].strip()
                    break

            # Check enabled/active status
            result = self._run_cmd(["systemctl", "is-enabled", unit_path.name])
            entry.enabled = result == "enabled"
            result = self._run_cmd(["systemctl", "is-active", unit_path.name])
            entry.active = result == "active"

            # Suspicious detection
            exec_lower = entry.exec_start.lower()
            for pattern in self.SUSPICIOUS_COMMANDS:
                if re.search(pattern.lower(), exec_lower):
                    entry.suspicious = True
                    entry.reason = f"Suspicious command pattern: {pattern}"
                    break

            if "/tmp/" in entry.exec_start or "/var/tmp/" in entry.exec_start:
                entry.suspicious = True
                entry.reason = "Executes from temp directory"

            if entry.exec_start and not os.path.exists(entry.exec_start.split()[0]):
                entry.suspicious = True
                entry.reason = "ExecStart binary does not exist"

            return entry
        except Exception as e:
            logger.debug("Failed to parse systemd unit %s: %s", unit_path, e)
            return None

    # ------------------------------------------------------------------
    # Cron Job Detection
    # ------------------------------------------------------------------

    def scan_cron_persistence(self) -> List[CronPersistence]:
        """Scan cron jobs for suspicious entries."""
        results = []
        for cron_dir in self.CRON_DIRS:
            if not cron_dir.exists():
                continue
            for cron_file in cron_dir.iterdir():
                if cron_file.is_file():
                    entries = self._parse_crontab(cron_file)
                    results.extend(entries)
        # Also check user crontab
        result = self._run_cmd(["crontab", "-l"])
        if result:
            for entry in self._parse_crontab_content(result, "current_user", "user crontab"):
                results.append(entry)
        return results

    def _parse_crontab(self, cron_file: Path) -> List[CronPersistence]:
        """Parse a crontab file."""
        try:
            content = cron_file.read_text()
            return self._parse_crontab_content(content, cron_file.name, str(cron_file))
        except Exception:
            return []

    def _parse_crontab_content(self, content: str, user: str, file_path: str) -> List[CronPersistence]:
        results = []
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("MAILTO") or "=" in line.split()[0] if line.split() else True:
                continue
            parts = line.split(None, 5)
            if len(parts) >= 6:
                schedule = " ".join(parts[:5])
                command = parts[5]
                entry = CronPersistence(
                    user=user, schedule=schedule, command=command, file_path=file_path,
                )
                cmd_lower = command.lower()
                for pattern in self.SUSPICIOUS_COMMANDS:
                    if re.search(pattern.lower(), cmd_lower):
                        entry.suspicious = True
                        entry.reason = f"Suspicious command: {pattern}"
                        break
                results.append(entry)
        return results

    # ------------------------------------------------------------------
    # Namespace / Sandbox Integration
    # ------------------------------------------------------------------

    def run_sandboxed(self, binary_path: str, work_dir: str, timeout_s: int = 30) -> Dict:
        """Run binary in a namespace sandbox using bubblewrap (bwrap)."""
        bwrap = shutil.which("bwrap")
        if not bwrap:
            return {"error": "bubblewrap not installed", "exit_code": -1}

        cmd = [
            bwrap,
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/bin", "/bin",
            "--symlink", "/usr/lib64", "/lib64" if os.path.exists("/lib64") else "/lib",
            "--bind", work_dir, "/tmp/sandbox",
            "--ro-bind", binary_path, "/tmp/binary",
            "--proc", "/proc",
            "--dev", "/dev",
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--", "/tmp/binary",
        ]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_s,
                cwd=work_dir, env={"HOME": "/tmp/sandbox", "PATH": "/usr/bin:/bin", "TMPDIR": "/tmp/sandbox"},
            )
            return {
                "exit_code": proc.returncode,
                "stdout": proc.stdout[:4096],
                "stderr": proc.stderr[:4096],
            }
        except subprocess.TimeoutExpired:
            return {"error": "timeout", "exit_code": -1}
        except Exception as e:
            return {"error": str(e), "exit_code": -1}

    # ------------------------------------------------------------------
    # AI Application Detection
    # ------------------------------------------------------------------

    def get_running_ai_processes(self) -> List[Dict[str, str]]:
        """Detect running AI-related processes."""
        results = []
        ai_indicators = [
            "chatgpt", "claude", "copilot", "cursor", "ollama",
            "lmstudio", "gpt4all", "openai", "localai", "text-generation",
            "vllm", "llama.cpp", "koboldcpp",
        ]
        result = self._run_cmd(["ps", "aux"])
        if result:
            for line in result.split("\n"):
                lower = line.lower()
                for indicator in ai_indicators:
                    if indicator in lower:
                        parts = line.split()
                        if len(parts) >= 11:
                            results.append({
                                "user": parts[0],
                                "pid": parts[1],
                                "cpu": parts[2],
                                "mem": parts[3],
                                "command": " ".join(parts[10:]),
                                "indicator": indicator,
                            })
                        break
        return results

    # ------------------------------------------------------------------
    # Auditd Integration
    # ------------------------------------------------------------------

    def add_audit_rule(self, rule: str) -> bool:
        """Add an auditd rule for monitoring."""
        result = self._run_cmd(["auditctl", "-a", rule])
        return result is not None

    def get_audit_events(self, key: str = "aishields", since: str = "recent") -> List[str]:
        """Get audit events by key."""
        result = self._run_cmd(
            ["ausearch", "-k", key, "--start", since, "-i"],
            timeout=15,
        )
        if result:
            return result.split("\n----\n")
        return []

    # ------------------------------------------------------------------
    # eBPF Support Check
    # ------------------------------------------------------------------

    def check_ebpf_support(self) -> Dict[str, bool]:
        """Check eBPF capabilities."""
        return {
            "btf_available": os.path.exists("/sys/kernel/btf/vmlinux"),
            "bpf_syscall": os.path.exists("/proc/sys/kernel/unprivileged_bpf_disabled"),
            "bpftool": shutil.which("bpftool") is not None,
            "bcc": shutil.which("bpftrace") is not None,
            "libbpf": os.path.exists("/usr/lib/libbpf.so") or os.path.exists("/usr/lib64/libbpf.so"),
        }
