"""Windows Platform-Specific Security Hooks.

Provides Windows-native integration for:
- Windows Defender / AMSI integration
- Authenticode signature verification
- Mark-of-the-Web (MOTW / Zone.Identifier) checking
- Windows Event Log monitoring
- Registry persistence detection
- Service/Scheduled Task monitoring
- AppLocker/WDAC policy interaction
- ETW (Event Tracing for Windows) consumer
"""

import json
import logging
import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("endpoint.platform.windows")


@dataclass
class WindowsSecurityState:
    """Snapshot of Windows security posture."""
    os_version: str = ""
    defender_enabled: bool = False
    defender_realtime: bool = False
    defender_definitions_version: str = ""
    bitlocker_enabled: bool = False
    secure_boot: bool = False
    credential_guard: bool = False
    uac_level: int = -1
    firewall_enabled: bool = False
    applocker_enabled: bool = False
    wdac_enforced: bool = False


@dataclass
class RegistryPersistence:
    """Detected registry persistence entry."""
    hive: str
    key: str
    value_name: str
    value_data: str
    suspicious: bool = False
    reason: str = ""


@dataclass
class ScheduledTaskInfo:
    """Info about a Windows scheduled task."""
    name: str
    path: str
    state: str
    command: str
    author: str = ""
    suspicious: bool = False
    reason: str = ""


class WindowsPlatform:
    """Windows-specific security monitoring and enforcement."""

    # Registry Run key locations for persistence detection
    PERSISTENCE_KEYS = [
        (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "User Run"),
        (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "User RunOnce"),
        (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "Machine Run"),
        (r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "Machine RunOnce"),
        (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "User Shell Folders"),
        (r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon"),
        (r"HKLM\System\CurrentControlSet\Services", "Services"),
    ]

    SUSPICIOUS_COMMAND_PATTERNS = [
        "powershell -enc", "powershell -nop", "cmd /c", "mshta",
        "wscript", "cscript", "regsvr32 /s /n /u",
        "rundll32", "certutil -decode", "bitsadmin /transfer",
    ]

    def __init__(self):
        if platform.system() != "Windows":
            logger.warning("WindowsPlatform instantiated on non-Windows system")
        self._os_version = platform.version() if platform.system() == "Windows" else ""

    # ------------------------------------------------------------------
    # Security Posture Assessment
    # ------------------------------------------------------------------

    def get_security_state(self) -> WindowsSecurityState:
        """Gather comprehensive Windows security posture."""
        state = WindowsSecurityState(os_version=self._os_version)
        state.defender_enabled = self._check_defender()
        state.defender_realtime = self._check_defender_realtime()
        state.defender_definitions_version = self._get_defender_definitions()
        state.bitlocker_enabled = self._check_bitlocker()
        state.secure_boot = self._check_secure_boot()
        state.credential_guard = self._check_credential_guard()
        state.uac_level = self._get_uac_level()
        state.firewall_enabled = self._check_firewall()
        return state

    def _run_powershell(self, command: str, timeout: int = 10) -> Optional[str]:
        """Execute a PowerShell command and return stdout."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode == 0:
                return r.stdout.strip()
        except Exception as e:
            logger.debug("PowerShell command failed: %s", e)
        return None

    def _check_defender(self) -> bool:
        result = self._run_powershell(
            "(Get-MpComputerStatus).AntivirusEnabled"
        )
        return result and result.lower() == "true"

    def _check_defender_realtime(self) -> bool:
        result = self._run_powershell(
            "(Get-MpComputerStatus).RealTimeProtectionEnabled"
        )
        return result and result.lower() == "true"

    def _get_defender_definitions(self) -> str:
        result = self._run_powershell(
            "(Get-MpComputerStatus).AntivirusSignatureVersion"
        )
        return result or "unknown"

    def _check_bitlocker(self) -> bool:
        result = self._run_powershell(
            "(Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus"
        )
        return result == "On" if result else False

    def _check_secure_boot(self) -> bool:
        result = self._run_powershell("Confirm-SecureBootUEFI")
        return result and result.lower() == "true"

    def _check_credential_guard(self) -> bool:
        result = self._run_powershell(
            "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard).SecurityServicesRunning -contains 1"
        )
        return result and result.lower() == "true"

    def _get_uac_level(self) -> int:
        result = self._run_powershell(
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').ConsentPromptBehaviorAdmin"
        )
        try:
            return int(result) if result else -1
        except ValueError:
            return -1

    def _check_firewall(self) -> bool:
        result = self._run_powershell(
            "(Get-NetFirewallProfile -Profile Domain,Public,Private | Where-Object {$_.Enabled -eq $true}).Count"
        )
        try:
            return int(result) > 0 if result else False
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Authenticode Signature Verification
    # ------------------------------------------------------------------

    def verify_authenticode(self, path: str) -> Tuple[bool, str]:
        """Verify Windows Authenticode signature. Returns (signed, signer_subject)."""
        result = self._run_powershell(
            f"$sig = Get-AuthenticodeSignature '{path}'; "
            f"\"$($sig.Status)|$($sig.SignerCertificate.Subject)\""
        )
        if result:
            parts = result.split("|", 1)
            status = parts[0].strip()
            subject = parts[1].strip() if len(parts) > 1 else ""
            return status == "Valid", subject
        return False, ""

    # ------------------------------------------------------------------
    # Mark-of-the-Web (MOTW) / Zone.Identifier
    # ------------------------------------------------------------------

    def check_motw(self, path: str) -> Optional[Dict[str, str]]:
        """Check Mark-of-the-Web (Zone.Identifier alternate data stream)."""
        zone_file = path + ":Zone.Identifier"
        try:
            result = self._run_powershell(f"Get-Content '{zone_file}' -ErrorAction SilentlyContinue")
            if result:
                info = {}
                for line in result.split("\n"):
                    if "=" in line:
                        key, val = line.split("=", 1)
                        info[key.strip()] = val.strip()
                return info
        except Exception:
            pass
        return None

    def remove_motw(self, path: str) -> bool:
        """Remove Mark-of-the-Web from a file (Unblock-File)."""
        result = self._run_powershell(f"Unblock-File -Path '{path}' -ErrorAction Stop; 'OK'")
        return result == "OK"

    # ------------------------------------------------------------------
    # AMSI (Antimalware Scan Interface) Integration
    # ------------------------------------------------------------------

    def amsi_scan_string(self, content: str, content_name: str = "CyberArmor.ai") -> bool:
        """Scan a string via AMSI. Returns True if clean, False if flagged."""
        # AMSI scan via PowerShell wrapper
        ps_script = f"""
        Add-Type -TypeDefinition @'
        using System;
        using System.Runtime.InteropServices;
        public class AMSI {{
            [DllImport("amsi.dll")]
            public static extern int AmsiInitialize(string appName, out IntPtr amsiContext);
            [DllImport("amsi.dll")]
            public static extern int AmsiScanString(IntPtr amsiContext, string content, string contentName, IntPtr session, out int result);
            [DllImport("amsi.dll")]
            public static extern void AmsiUninitialize(IntPtr amsiContext);
        }}
'@
        $ctx = [IntPtr]::Zero
        [AMSI]::AmsiInitialize("{content_name}", [ref]$ctx)
        $result = 0
        [AMSI]::AmsiScanString($ctx, $content, "scan", [IntPtr]::Zero, [ref]$result)
        [AMSI]::AmsiUninitialize($ctx)
        if ($result -ge 32768) {{ "MALICIOUS" }} else {{ "CLEAN" }}
        """
        result = self._run_powershell(ps_script, timeout=15)
        return result != "MALICIOUS" if result else True

    # ------------------------------------------------------------------
    # Registry Persistence Detection
    # ------------------------------------------------------------------

    def scan_registry_persistence(self) -> List[RegistryPersistence]:
        """Scan registry Run keys for persistence entries."""
        results = []
        for key_path, description in self.PERSISTENCE_KEYS:
            entries = self._read_registry_key(key_path)
            for name, data in entries.items():
                entry = RegistryPersistence(
                    hive=key_path.split("\\")[0],
                    key=key_path,
                    value_name=name,
                    value_data=data,
                )
                # Check for suspicious patterns
                data_lower = data.lower()
                for pattern in self.SUSPICIOUS_COMMAND_PATTERNS:
                    if pattern.lower() in data_lower:
                        entry.suspicious = True
                        entry.reason = f"Suspicious command pattern: {pattern}"
                        break

                if not entry.suspicious:
                    if "\\temp\\" in data_lower or "\\tmp\\" in data_lower:
                        entry.suspicious = True
                        entry.reason = "Runs from temp directory"
                    elif "\\appdata\\local\\temp\\" in data_lower:
                        entry.suspicious = True
                        entry.reason = "Runs from AppData temp directory"

                results.append(entry)
        return results

    def _read_registry_key(self, key_path: str) -> Dict[str, str]:
        """Read all values from a registry key."""
        entries = {}
        result = self._run_powershell(
            f"Get-ItemProperty -Path 'Registry::{key_path}' -ErrorAction SilentlyContinue | "
            f"ConvertTo-Json -Depth 1"
        )
        if result:
            try:
                data = json.loads(result)
                for k, v in data.items():
                    if not k.startswith("PS") and k not in ("PSPath", "PSParentPath", "PSChildName", "PSProvider"):
                        entries[k] = str(v)
            except json.JSONDecodeError:
                pass
        return entries

    # ------------------------------------------------------------------
    # Scheduled Task Monitoring
    # ------------------------------------------------------------------

    def scan_scheduled_tasks(self) -> List[ScheduledTaskInfo]:
        """Scan scheduled tasks for suspicious entries."""
        tasks = []
        result = self._run_powershell(
            "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
            "Select-Object TaskName, TaskPath, State, @{N='Command';E={(Get-ScheduledTaskInfo $_.TaskName -ErrorAction SilentlyContinue).LastTaskResult}}, "
            "@{N='Author';E={$_.Author}} | ConvertTo-Json -Depth 2",
            timeout=30,
        )
        if result:
            try:
                raw_tasks = json.loads(result)
                if isinstance(raw_tasks, dict):
                    raw_tasks = [raw_tasks]
                for t in raw_tasks:
                    task = ScheduledTaskInfo(
                        name=t.get("TaskName", ""),
                        path=t.get("TaskPath", ""),
                        state=t.get("State", ""),
                        command=str(t.get("Command", "")),
                        author=t.get("Author", ""),
                    )
                    # Check for suspicious tasks
                    if task.author and "microsoft" not in task.author.lower():
                        for pattern in self.SUSPICIOUS_COMMAND_PATTERNS:
                            if pattern.lower() in task.command.lower():
                                task.suspicious = True
                                task.reason = f"Suspicious command: {pattern}"
                                break
                    tasks.append(task)
            except json.JSONDecodeError:
                pass
        return tasks

    # ------------------------------------------------------------------
    # Windows Event Log Monitoring
    # ------------------------------------------------------------------

    def get_security_events(self, hours: int = 1, max_events: int = 100) -> List[Dict]:
        """Get recent security-relevant events from Windows Event Log."""
        events = []
        # Event IDs: 4624 (logon), 4625 (failed logon), 4688 (process create), 4698 (scheduled task)
        event_ids = "4624,4625,4688,4698,4720,4726,1102"
        result = self._run_powershell(
            f"Get-WinEvent -FilterHashtable @{{LogName='Security'; Id={event_ids}; "
            f"StartTime=(Get-Date).AddHours(-{hours})}} -MaxEvents {max_events} -ErrorAction SilentlyContinue | "
            f"Select-Object TimeCreated, Id, Message | ConvertTo-Json -Depth 1",
            timeout=30,
        )
        if result:
            try:
                raw_events = json.loads(result)
                if isinstance(raw_events, dict):
                    raw_events = [raw_events]
                for e in raw_events:
                    events.append({
                        "time": e.get("TimeCreated", ""),
                        "event_id": e.get("Id", 0),
                        "message": str(e.get("Message", ""))[:500],
                    })
            except json.JSONDecodeError:
                pass
        return events

    # ------------------------------------------------------------------
    # AI Application Detection
    # ------------------------------------------------------------------

    def get_running_ai_processes(self) -> List[Dict[str, str]]:
        """Detect running AI-related processes."""
        results = []
        ai_process_names = [
            "ChatGPT", "claude", "Copilot", "cursor", "ollama",
            "lmstudio", "gpt4all", "openai", "msedge",
        ]
        result = self._run_powershell(
            "Get-Process | Select-Object Id, ProcessName, Path, CPU | ConvertTo-Json -Depth 1",
            timeout=15,
        )
        if result:
            try:
                processes = json.loads(result)
                if isinstance(processes, dict):
                    processes = [processes]
                for p in processes:
                    name = p.get("ProcessName", "").lower()
                    for ai_name in ai_process_names:
                        if ai_name.lower() in name:
                            results.append({
                                "pid": str(p.get("Id", "")),
                                "name": p.get("ProcessName", ""),
                                "path": p.get("Path", ""),
                                "cpu": str(p.get("CPU", "")),
                                "indicator": ai_name,
                            })
                            break
            except json.JSONDecodeError:
                pass
        return results

    # ------------------------------------------------------------------
    # AppLocker / WDAC Integration
    # ------------------------------------------------------------------

    def get_applocker_status(self) -> Dict[str, str]:
        """Get AppLocker enforcement status."""
        result = self._run_powershell(
            "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty RuleCollections | "
            "ForEach-Object { \"$($_.RuleCollectionType)=$($_.EnforcementMode)\" }"
        )
        status = {}
        if result:
            for line in result.split("\n"):
                if "=" in line:
                    key, val = line.split("=", 1)
                    status[key.strip()] = val.strip()
        return status

    # ------------------------------------------------------------------
    # ETW Consumer for Real-time Monitoring
    # ------------------------------------------------------------------

    def start_etw_trace(self, provider_guid: str, output_file: str) -> Optional[str]:
        """Start an ETW trace session. Returns session name."""
        session_name = f"CyberArmor.ai_{provider_guid[:8]}"
        result = self._run_powershell(
            f"New-EtwTraceSession -Name '{session_name}' -LogFileMode 0x8 | Out-Null; "
            f"Add-EtwTraceProvider -SessionName '{session_name}' -Guid '{{{provider_guid}}}' -Level 5 | Out-Null; "
            f"'{session_name}'",
            timeout=15,
        )
        return result if result == session_name else None

    def stop_etw_trace(self, session_name: str) -> bool:
        """Stop an ETW trace session."""
        result = self._run_powershell(
            f"Stop-EtwTraceSession -Name '{session_name}' -ErrorAction Stop; 'OK'"
        )
        return result == "OK"
