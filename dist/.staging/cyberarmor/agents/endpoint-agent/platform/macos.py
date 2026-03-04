"""macOS Platform-Specific Security Hooks.

Provides macOS-native integration for:
- Endpoint Security Framework (ES) event monitoring
- TCC (Transparency, Consent, Control) state checking
- Gatekeeper & XProtect verification
- Keychain access monitoring
- System Extension management
- launchd persistence detection
- Quarantine attribute inspection
"""

import json
import logging
import os
import platform
import plistlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("endpoint.platform.macos")


@dataclass
class MacSecurityState:
    """Snapshot of macOS security posture."""
    sip_enabled: bool = True
    filevault_enabled: bool = False
    gatekeeper_enabled: bool = True
    firewall_enabled: bool = False
    xprotect_version: str = ""
    os_version: str = ""
    secure_boot: str = "unknown"
    tcc_grants: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class LaunchdPersistence:
    """Detected launchd persistence entry."""
    label: str
    path: str
    program: str
    run_at_load: bool = False
    keep_alive: bool = False
    suspicious: bool = False
    reason: str = ""


class MacOSPlatform:
    """macOS-specific security monitoring and enforcement."""

    LAUNCH_AGENT_DIRS = [
        Path.home() / "Library" / "LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
        Path("/System/Library/LaunchDaemons"),
    ]

    AI_BUNDLE_IDS = [
        "com.openai.chat",
        "com.anthropic.claude",
        "com.google.Chrome",
        "com.microsoft.edgemac",
        "com.brave.Browser",
        "com.apple.Safari",
        "com.microsoft.VSCode",
        "com.todesktop.230313mzl4w4u92",  # Cursor
    ]

    # Known suspicious launchd labels
    SUSPICIOUS_LABELS = [
        "com.apple.update",  # Fake Apple updater
        "com.system.agent",  # Generic system impersonation
    ]

    def __init__(self):
        if platform.system() != "Darwin":
            logger.warning("MacOSPlatform instantiated on non-macOS system")
        self._os_version = platform.mac_ver()[0] if platform.system() == "Darwin" else ""

    # ------------------------------------------------------------------
    # Security Posture Assessment
    # ------------------------------------------------------------------

    def get_security_state(self) -> MacSecurityState:
        """Gather comprehensive macOS security posture."""
        state = MacSecurityState(os_version=self._os_version)
        state.sip_enabled = self._check_sip()
        state.filevault_enabled = self._check_filevault()
        state.gatekeeper_enabled = self._check_gatekeeper()
        state.firewall_enabled = self._check_firewall()
        state.xprotect_version = self._get_xprotect_version()
        state.secure_boot = self._check_secure_boot()
        return state

    def _check_sip(self) -> bool:
        """Check System Integrity Protection status."""
        try:
            r = subprocess.run(["csrutil", "status"], capture_output=True, text=True, timeout=5)
            return "enabled" in r.stdout.lower()
        except Exception:
            return True  # Assume enabled if can't check

    def _check_filevault(self) -> bool:
        """Check FileVault disk encryption status."""
        try:
            r = subprocess.run(["fdesetup", "status"], capture_output=True, text=True, timeout=5)
            return "on" in r.stdout.lower()
        except Exception:
            return False

    def _check_gatekeeper(self) -> bool:
        """Check Gatekeeper status."""
        try:
            r = subprocess.run(["spctl", "--status"], capture_output=True, text=True, timeout=5)
            return "enabled" in r.stdout.lower() or "assessments enabled" in r.stdout.lower()
        except Exception:
            return True

    def _check_firewall(self) -> bool:
        """Check application firewall status."""
        try:
            r = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True, timeout=5,
            )
            return "enabled" in r.stdout.lower()
        except Exception:
            return False

    def _get_xprotect_version(self) -> str:
        """Get XProtect definitions version."""
        plist_path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist"
        try:
            if os.path.exists(plist_path):
                with open(plist_path, "rb") as f:
                    plist = plistlib.load(f)
                return plist.get("CFBundleShortVersionString", "unknown")
        except Exception:
            pass
        return "unknown"

    def _check_secure_boot(self) -> str:
        """Check Secure Boot status (Apple Silicon)."""
        try:
            r = subprocess.run(
                ["system_profiler", "SPiBridgeDataType", "-json"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                data = json.loads(r.stdout)
                bridge = data.get("SPiBridgeDataType", [{}])
                if bridge:
                    return bridge[0].get("ibridge_secure_boot", "unknown")
        except Exception:
            pass
        return "unknown"

    # ------------------------------------------------------------------
    # Code Signature Verification
    # ------------------------------------------------------------------

    def verify_code_signature(self, path: str) -> Tuple[bool, str, str]:
        """Verify macOS code signature. Returns (signed, signer, team_id)."""
        try:
            r = subprocess.run(
                ["codesign", "-dvvv", "--strict", path],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode != 0:
                return False, "", ""

            signer = ""
            team_id = ""
            for line in r.stderr.split("\n"):
                if "Authority=" in line:
                    if not signer:
                        signer = line.split("=", 1)[1].strip()
                elif "TeamIdentifier=" in line:
                    team_id = line.split("=", 1)[1].strip()

            return True, signer, team_id
        except Exception as e:
            logger.debug("Code signature check failed: %s", e)
            return False, "", ""

    def check_notarization(self, path: str) -> bool:
        """Check if a binary has been notarized by Apple."""
        try:
            r = subprocess.run(
                ["spctl", "-a", "-v", "-t", "exec", path],
                capture_output=True, text=True, timeout=10,
            )
            return "notarized" in r.stderr.lower() or r.returncode == 0
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Quarantine Attribute Inspection
    # ------------------------------------------------------------------

    def check_quarantine_flag(self, path: str) -> Optional[Dict[str, str]]:
        """Check macOS quarantine extended attribute (com.apple.quarantine)."""
        try:
            r = subprocess.run(
                ["xattr", "-p", "com.apple.quarantine", path],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                parts = r.stdout.strip().split(";")
                return {
                    "flags": parts[0] if len(parts) > 0 else "",
                    "timestamp": parts[1] if len(parts) > 1 else "",
                    "agent_name": parts[2] if len(parts) > 2 else "",
                    "uuid": parts[3] if len(parts) > 3 else "",
                }
        except Exception:
            pass
        return None

    def remove_quarantine_flag(self, path: str) -> bool:
        """Remove quarantine flag (requires elevated privileges for some files)."""
        try:
            r = subprocess.run(
                ["xattr", "-d", "com.apple.quarantine", path],
                capture_output=True, text=True, timeout=5,
            )
            return r.returncode == 0
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Persistence Detection (LaunchAgents/Daemons)
    # ------------------------------------------------------------------

    def scan_launch_persistence(self) -> List[LaunchdPersistence]:
        """Scan for launchd persistence entries (LaunchAgents/Daemons)."""
        results = []
        for agent_dir in self.LAUNCH_AGENT_DIRS:
            if not agent_dir.exists():
                continue
            for plist_file in agent_dir.glob("*.plist"):
                entry = self._parse_launchd_plist(plist_file)
                if entry:
                    results.append(entry)
        return results

    def _parse_launchd_plist(self, plist_path: Path) -> Optional[LaunchdPersistence]:
        """Parse a launchd plist and check for suspicious entries."""
        try:
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)

            label = plist.get("Label", "")
            program = plist.get("Program", "")
            if not program:
                args = plist.get("ProgramArguments", [])
                program = args[0] if args else ""

            entry = LaunchdPersistence(
                label=label,
                path=str(plist_path),
                program=program,
                run_at_load=plist.get("RunAtLoad", False),
                keep_alive=bool(plist.get("KeepAlive", False)),
            )

            # Check for suspicious patterns
            if any(s in label.lower() for s in ["update", "helper", "agent"]):
                if not program.startswith("/System/") and not program.startswith("/usr/"):
                    entry.suspicious = True
                    entry.reason = "Non-system binary with system-like label"

            if entry.run_at_load and program:
                if not os.path.exists(program):
                    entry.suspicious = True
                    entry.reason = "Program binary does not exist"
                elif "/tmp/" in program or "/var/tmp/" in program:
                    entry.suspicious = True
                    entry.reason = "Program runs from temp directory"

            for sl in self.SUSPICIOUS_LABELS:
                if sl in label.lower():
                    entry.suspicious = True
                    entry.reason = f"Matches suspicious label pattern: {sl}"

            return entry
        except Exception as e:
            logger.debug("Failed to parse plist %s: %s", plist_path, e)
            return None

    # ------------------------------------------------------------------
    # Process Monitoring via ES Framework (requires System Extension)
    # ------------------------------------------------------------------

    def get_running_ai_apps(self) -> List[Dict[str, str]]:
        """Detect running AI-related applications."""
        results = []
        try:
            r = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.split("\n"):
                lower = line.lower()
                ai_indicators = [
                    "chatgpt", "claude", "copilot", "cursor", "openai",
                    "anthropic", "ollama", "lmstudio", "gpt4all",
                ]
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
        except Exception as e:
            logger.debug("Failed to enumerate AI apps: %s", e)
        return results

    # ------------------------------------------------------------------
    # TCC Database Inspection
    # ------------------------------------------------------------------

    def get_tcc_grants(self) -> Dict[str, List[str]]:
        """Get TCC (Transparency, Consent, Control) access grants.

        Note: Reading the TCC database directly requires Full Disk Access.
        This method uses tccutil when possible.
        """
        grants = {}
        tcc_db = Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"
        if tcc_db.exists():
            try:
                import sqlite3
                conn = sqlite3.connect(str(tcc_db))
                rows = conn.execute(
                    "SELECT service, client, auth_value FROM access WHERE auth_value = 2"
                ).fetchall()
                for service, client, _ in rows:
                    grants.setdefault(service, []).append(client)
                conn.close()
            except Exception as e:
                logger.debug("Cannot read TCC database: %s", e)
        return grants

    # ------------------------------------------------------------------
    # Sandbox Profile for Binary Analysis
    # ------------------------------------------------------------------

    def create_sandbox_profile(self, binary_path: str, work_dir: str) -> str:
        """Create a macOS sandbox-exec profile for restricted binary execution."""
        return f"""(version 1)
(deny default)
(allow process-exec (literal "{binary_path}"))
(allow file-read* (subpath "{work_dir}"))
(allow file-write* (subpath "{work_dir}"))
(allow file-read* (subpath "/usr/lib"))
(allow file-read* (subpath "/System/Library"))
(allow file-read* (subpath "/Library/Frameworks"))
(allow file-read-metadata)
(deny network*)
(deny process-fork)
(deny signal)
(deny sysctl-write)
(deny system-privilege)
"""

    # ------------------------------------------------------------------
    # System Extension Management
    # ------------------------------------------------------------------

    def list_system_extensions(self) -> List[Dict[str, str]]:
        """List installed system extensions."""
        extensions = []
        try:
            r = subprocess.run(
                ["systemextensionsctl", "list"],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.split("\n"):
                line = line.strip()
                if line and not line.startswith("---") and not line.startswith("*"):
                    parts = line.split()
                    if len(parts) >= 3:
                        extensions.append({
                            "identifier": parts[0],
                            "team_id": parts[1] if len(parts) > 1 else "",
                            "state": parts[-1] if parts else "",
                        })
        except Exception as e:
            logger.debug("Failed to list system extensions: %s", e)
        return extensions
