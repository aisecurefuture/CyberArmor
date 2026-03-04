"""AI Tool Detector -- discovers installed AI tools, browser extensions, and IDE plugins.

Maintains a database of known AI tools (process names, install paths, registry
keys, macOS bundle IDs) and periodically scans the system to report installed
and running AI software.  Supports tenant-configurable allow / block lists and
zero-day detection for unknown tools connecting to AI-like APIs.
"""

from __future__ import annotations

import asyncio
import glob
import json
import logging
import os
import platform
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

if TYPE_CHECKING:
    from agent import EndpointAgent

logger = logging.getLogger("aishields.monitors.ai_tool_detector")

# ---------------------------------------------------------------------------
# Known AI tool database
# ---------------------------------------------------------------------------


@dataclass
class AIToolSignature:
    """Signature for a known AI tool."""

    name: str
    vendor: str
    category: str  # desktop_app, cli, ide_extension, browser_extension, server
    # Detection vectors (any match counts)
    process_names: List[str] = field(default_factory=list)
    macos_bundle_ids: List[str] = field(default_factory=list)
    windows_registry_keys: List[str] = field(default_factory=list)
    install_paths_unix: List[str] = field(default_factory=list)
    install_paths_windows: List[str] = field(default_factory=list)
    browser_extension_ids: Dict[str, List[str]] = field(default_factory=dict)  # browser -> [ext_id]
    ide_extension_ids: Dict[str, List[str]] = field(default_factory=dict)  # ide -> [ext_id]


# Comprehensive AI tool database
KNOWN_AI_TOOLS: List[AIToolSignature] = [
    # --- Desktop applications ---
    AIToolSignature(
        name="ChatGPT Desktop",
        vendor="OpenAI",
        category="desktop_app",
        process_names=["ChatGPT", "chatgpt"],
        macos_bundle_ids=["com.openai.chat"],
        install_paths_unix=["~/Applications/ChatGPT.app", "/Applications/ChatGPT.app"],
        install_paths_windows=[
            r"%LOCALAPPDATA%\Programs\ChatGPT\ChatGPT.exe",
        ],
    ),
    AIToolSignature(
        name="Claude Desktop",
        vendor="Anthropic",
        category="desktop_app",
        process_names=["Claude", "claude"],
        macos_bundle_ids=["com.anthropic.claude"],
        install_paths_unix=["~/Applications/Claude.app", "/Applications/Claude.app"],
        install_paths_windows=[
            r"%LOCALAPPDATA%\Programs\Claude\Claude.exe",
        ],
    ),
    AIToolSignature(
        name="Cursor AI",
        vendor="Cursor",
        category="desktop_app",
        process_names=["Cursor", "cursor"],
        macos_bundle_ids=["com.todesktop.230313mzl4w4u92"],
        install_paths_unix=["~/Applications/Cursor.app", "/Applications/Cursor.app"],
        install_paths_windows=[
            r"%LOCALAPPDATA%\Programs\cursor\Cursor.exe",
        ],
    ),
    AIToolSignature(
        name="LM Studio",
        vendor="LM Studio",
        category="desktop_app",
        process_names=["LM Studio", "lm-studio", "lmstudio"],
        macos_bundle_ids=["com.lmstudio.app"],
        install_paths_unix=["/Applications/LM Studio.app"],
        install_paths_windows=[
            r"%LOCALAPPDATA%\Programs\lm-studio\LM Studio.exe",
        ],
    ),
    AIToolSignature(
        name="Jan AI",
        vendor="Jan",
        category="desktop_app",
        process_names=["Jan", "jan"],
        macos_bundle_ids=["jan.ai"],
        install_paths_unix=["/Applications/Jan.app"],
        install_paths_windows=[
            r"%LOCALAPPDATA%\Programs\jan\Jan.exe",
        ],
    ),
    AIToolSignature(
        name="GPT4All",
        vendor="Nomic",
        category="desktop_app",
        process_names=["gpt4all", "chat"],
        install_paths_unix=["/Applications/GPT4All.app", "~/.local/bin/gpt4all"],
        install_paths_windows=[
            r"%LOCALAPPDATA%\nomic.ai\GPT4All\bin\chat.exe",
        ],
    ),

    # --- CLI tools ---
    AIToolSignature(
        name="Ollama",
        vendor="Ollama",
        category="cli",
        process_names=["ollama"],
        install_paths_unix=["/usr/local/bin/ollama", "/usr/bin/ollama", "~/.ollama"],
        install_paths_windows=[
            r"%LOCALAPPDATA%\Ollama\ollama.exe",
        ],
    ),
    AIToolSignature(
        name="llama.cpp",
        vendor="ggerganov",
        category="cli",
        process_names=["llama-server", "llama-cli", "main"],
        install_paths_unix=["/usr/local/bin/llama-server", "/usr/local/bin/llama-cli"],
    ),
    AIToolSignature(
        name="LocalAI",
        vendor="LocalAI",
        category="server",
        process_names=["local-ai"],
        install_paths_unix=["/usr/local/bin/local-ai"],
    ),
    AIToolSignature(
        name="OpenClaw AI",
        vendor="OpenClaw",
        category="desktop_app",
        process_names=["openclaw"],
        install_paths_unix=["/usr/local/bin/openclaw"],
    ),

    # --- IDE extensions ---
    AIToolSignature(
        name="GitHub Copilot",
        vendor="GitHub",
        category="ide_extension",
        process_names=["copilot-agent"],
        ide_extension_ids={
            "vscode": ["GitHub.copilot", "GitHub.copilot-chat"],
            "jetbrains": ["com.github.copilot"],
            "neovim": ["copilot.vim"],
        },
    ),
    AIToolSignature(
        name="Cody AI",
        vendor="Sourcegraph",
        category="ide_extension",
        ide_extension_ids={
            "vscode": ["sourcegraph.cody-ai"],
            "jetbrains": ["com.sourcegraph.cody"],
        },
    ),
    AIToolSignature(
        name="Tabnine",
        vendor="Tabnine",
        category="ide_extension",
        process_names=["TabNine", "tabnine"],
        ide_extension_ids={
            "vscode": ["TabNine.tabnine-vscode"],
            "jetbrains": ["com.tabnine.TabNine"],
        },
    ),
    AIToolSignature(
        name="Amazon CodeWhisperer",
        vendor="Amazon",
        category="ide_extension",
        ide_extension_ids={
            "vscode": ["AmazonWebServices.aws-toolkit-vscode"],
            "jetbrains": ["com.amazonaws.codewhisperer"],
        },
    ),
    AIToolSignature(
        name="Continue.dev",
        vendor="Continue",
        category="ide_extension",
        ide_extension_ids={
            "vscode": ["Continue.continue"],
        },
    ),

    # --- Browser extensions ---
    AIToolSignature(
        name="ChatGPT Browser Extension",
        vendor="OpenAI",
        category="browser_extension",
        browser_extension_ids={
            "chrome": ["jjkdckbhmofeigdgjfbgpdahbcoienng"],
            "firefox": ["chatgpt@openai.com"],
        },
    ),
    AIToolSignature(
        name="Monica AI",
        vendor="Monica",
        category="browser_extension",
        browser_extension_ids={
            "chrome": ["ofhbbkphhbklhfoeikjpcbhemlocgigb"],
        },
    ),
    AIToolSignature(
        name="Perplexity AI Extension",
        vendor="Perplexity",
        category="browser_extension",
        browser_extension_ids={
            "chrome": ["hlgbcneanomplepojfcnclggenpcoldo"],
        },
    ),
]


@dataclass
class DetectedTool:
    """A detected AI tool on the system."""

    signature: AIToolSignature
    detection_method: str  # process, path, registry, bundle_id, extension
    detail: str  # e.g. the actual path or process name found
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    allowed: bool = True  # set by policy


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class AIToolDetector:
    """Periodically scans the system for installed and running AI tools.

    Parameters
    ----------
    agent : EndpointAgent
        Parent agent for telemetry, policy access, and configuration.
    scan_interval : float
        Seconds between full scans (default 120).
    """

    def __init__(
        self,
        agent: EndpointAgent,
        scan_interval: float = 120.0,
    ) -> None:
        self._agent = agent
        self._scan_interval = scan_interval
        self._detected: Dict[str, DetectedTool] = {}
        self._allow_list: Set[str] = set()
        self._block_list: Set[str] = set()
        self._system = platform.system()

    # ------------------------------------------------------------------
    # Policy integration
    # ------------------------------------------------------------------

    def update_policy_lists(
        self, allow: Optional[List[str]] = None, block: Optional[List[str]] = None
    ) -> None:
        """Update the allow/block lists from tenant policy."""
        if allow is not None:
            self._allow_list = set(allow)
        if block is not None:
            self._block_list = set(block)

    def _is_allowed(self, tool_name: str) -> bool:
        """Check if a tool is allowed by policy.

        Logic:
        * If a block list is defined and tool is on it -> blocked
        * If an allow list is defined and tool is NOT on it -> blocked
        * Otherwise -> allowed
        """
        if tool_name in self._block_list:
            return False
        if self._allow_list and tool_name not in self._allow_list:
            return False
        return True

    # ------------------------------------------------------------------
    # Scanning methods
    # ------------------------------------------------------------------

    def _scan_install_paths(self, sig: AIToolSignature) -> Optional[DetectedTool]:
        """Check if any known install paths exist for a tool."""
        paths: List[str] = []
        if self._system == "Windows":
            paths = [os.path.expandvars(p) for p in sig.install_paths_windows]
        else:
            paths = [os.path.expanduser(p) for p in sig.install_paths_unix]

        for path in paths:
            if os.path.exists(path):
                return DetectedTool(
                    signature=sig,
                    detection_method="path",
                    detail=path,
                    allowed=self._is_allowed(sig.name),
                )
        return None

    def _scan_macos_bundle_ids(self, sig: AIToolSignature) -> Optional[DetectedTool]:
        """On macOS, check for apps by bundle ID using mdfind."""
        if self._system != "Darwin" or not sig.macos_bundle_ids:
            return None
        for bundle_id in sig.macos_bundle_ids:
            try:
                import subprocess

                result = subprocess.run(
                    ["mdfind", f"kMDItemCFBundleIdentifier == '{bundle_id}'"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.stdout.strip():
                    return DetectedTool(
                        signature=sig,
                        detection_method="bundle_id",
                        detail=f"{bundle_id} -> {result.stdout.strip().splitlines()[0]}",
                        allowed=self._is_allowed(sig.name),
                    )
            except Exception:
                continue
        return None

    def _scan_windows_registry(self, sig: AIToolSignature) -> Optional[DetectedTool]:
        """On Windows, check registry keys for installed AI tools."""
        if self._system != "Windows" or not sig.windows_registry_keys:
            return None
        try:
            import winreg  # type: ignore[import-not-found]

            for key_path in sig.windows_registry_keys:
                try:
                    hive, subkey = key_path.split("\\", 1)
                    hive_map = {
                        "HKLM": winreg.HKEY_LOCAL_MACHINE,
                        "HKCU": winreg.HKEY_CURRENT_USER,
                    }
                    hive_handle = hive_map.get(hive, winreg.HKEY_LOCAL_MACHINE)
                    winreg.OpenKey(hive_handle, subkey)
                    return DetectedTool(
                        signature=sig,
                        detection_method="registry",
                        detail=key_path,
                        allowed=self._is_allowed(sig.name),
                    )
                except FileNotFoundError:
                    continue
        except ImportError:
            pass
        return None

    def _scan_vscode_extensions(self) -> List[DetectedTool]:
        """Scan VS Code extensions directory for AI-related extensions."""
        detections: List[DetectedTool] = []
        extensions_dir = Path.home() / ".vscode" / "extensions"
        if not extensions_dir.exists():
            return detections

        installed_ext_dirs = {d.name.lower() for d in extensions_dir.iterdir() if d.is_dir()}

        for sig in KNOWN_AI_TOOLS:
            vscode_ids = sig.ide_extension_ids.get("vscode", [])
            for ext_id in vscode_ids:
                ext_id_lower = ext_id.lower()
                for installed in installed_ext_dirs:
                    if installed.startswith(ext_id_lower):
                        detections.append(
                            DetectedTool(
                                signature=sig,
                                detection_method="ide_extension_vscode",
                                detail=f"vscode:{ext_id}",
                                allowed=self._is_allowed(sig.name),
                            )
                        )
                        break
        return detections

    def _scan_chrome_extensions(self) -> List[DetectedTool]:
        """Scan Chrome extension directories for known AI extensions."""
        detections: List[DetectedTool] = []

        if self._system == "Darwin":
            chrome_ext_base = Path.home() / "Library" / "Application Support" / "Google" / "Chrome"
        elif self._system == "Windows":
            chrome_ext_base = Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data"
        else:
            chrome_ext_base = Path.home() / ".config" / "google-chrome"

        # Check Default and numbered profiles
        profiles = ["Default"] + [f"Profile {i}" for i in range(1, 6)]
        for profile in profiles:
            ext_dir = chrome_ext_base / profile / "Extensions"
            if not ext_dir.exists():
                continue
            installed_ids = {d.name for d in ext_dir.iterdir() if d.is_dir()}

            for sig in KNOWN_AI_TOOLS:
                chrome_ids = sig.browser_extension_ids.get("chrome", [])
                for ext_id in chrome_ids:
                    if ext_id in installed_ids:
                        detections.append(
                            DetectedTool(
                                signature=sig,
                                detection_method="browser_extension_chrome",
                                detail=f"chrome:{ext_id} (profile={profile})",
                                allowed=self._is_allowed(sig.name),
                            )
                        )

        return detections

    # ------------------------------------------------------------------
    # Zero-day detection
    # ------------------------------------------------------------------

    async def _zero_day_check(self) -> None:
        """Flag processes with active connections to AI-like domains that do
        not match any known AI tool signature.

        This provides early warning for novel or unauthorized AI tools.
        """
        try:
            import psutil as _psutil

            known_process_names: Set[str] = set()
            for sig in KNOWN_AI_TOOLS:
                for pn in sig.process_names:
                    known_process_names.add(pn.lower())

            ai_api_patterns = [
                re.compile(r"(?i)openai\.com"),
                re.compile(r"(?i)anthropic\.com"),
                re.compile(r"(?i)googleapis\.com.*generat"),
                re.compile(r"(?i)huggingface\.co"),
                re.compile(r"(?i)replicate\.com"),
                re.compile(r"(?i)together\.xyz"),
                re.compile(r"(?i)groq\.com"),
                re.compile(r"(?i)mistral\.ai"),
                re.compile(r"(?i)cohere\.(ai|com)"),
                re.compile(r"(?i)openclaw\.ai"),
            ]

            for conn in _psutil.net_connections(kind="tcp"):
                if conn.status != "ESTABLISHED" or conn.raddr is None or conn.pid is None:
                    continue
                try:
                    proc = _psutil.Process(conn.pid)
                    proc_name = proc.name().lower()
                except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                    continue

                if proc_name in known_process_names:
                    continue

                # Reverse-resolve and check
                try:
                    hostname, _, _ = __import__("socket").gethostbyaddr(conn.raddr.ip)
                except Exception:
                    continue

                for pat in ai_api_patterns:
                    if pat.search(hostname):
                        key = f"zero_day:{proc_name}:{conn.raddr.ip}"
                        if key not in self._detected:
                            logger.warning(
                                "Zero-day AI tool detected: process=%s connecting to %s (%s)",
                                proc_name,
                                hostname,
                                conn.raddr.ip,
                            )
                            self._detected[key] = DetectedTool(
                                signature=AIToolSignature(
                                    name=f"Unknown ({proc_name})",
                                    vendor="Unknown",
                                    category="unknown",
                                    process_names=[proc_name],
                                ),
                                detection_method="zero_day_network",
                                detail=f"{proc_name} -> {hostname}",
                                allowed=False,
                            )
                            await self._emit_event(
                                "zero_day_ai_tool_detected",
                                {
                                    "process_name": proc_name,
                                    "pid": conn.pid,
                                    "remote_host": hostname,
                                    "remote_ip": conn.raddr.ip,
                                    "severity": "critical",
                                },
                            )
                        break
        except Exception as exc:
            logger.debug("Zero-day check error: %s", exc)

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    async def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        event = {
            "source": "ai_tool_detector",
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **data,
        }
        await self._agent.report_event(event)

    # ------------------------------------------------------------------
    # Full scan
    # ------------------------------------------------------------------

    async def _full_scan(self) -> None:
        """Perform a complete scan of the system for AI tools."""
        new_detections: List[DetectedTool] = []

        for sig in KNOWN_AI_TOOLS:
            # Path scan
            det = self._scan_install_paths(sig)
            if det:
                new_detections.append(det)

            # macOS bundle ID
            det = self._scan_macos_bundle_ids(sig)
            if det:
                new_detections.append(det)

            # Windows registry
            det = self._scan_windows_registry(sig)
            if det:
                new_detections.append(det)

        # IDE extensions
        new_detections.extend(self._scan_vscode_extensions())

        # Browser extensions
        new_detections.extend(self._scan_chrome_extensions())

        # Report new detections
        for det in new_detections:
            key = f"{det.signature.name}:{det.detection_method}:{det.detail}"
            if key not in self._detected:
                self._detected[key] = det
                severity = "critical" if not det.allowed else "medium"
                logger.info(
                    "AI tool found: %s via %s (%s) allowed=%s",
                    det.signature.name,
                    det.detection_method,
                    det.detail,
                    det.allowed,
                )
                await self._emit_event(
                    "ai_tool_installed" if det.allowed else "unauthorized_ai_tool_detected",
                    {
                        "tool_name": det.signature.name,
                        "vendor": det.signature.vendor,
                        "category": det.signature.category,
                        "detection_method": det.detection_method,
                        "detail": det.detail,
                        "allowed": det.allowed,
                        "severity": severity,
                    },
                )

        # Zero-day detection
        await self._zero_day_check()

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Periodically scan for AI tools until cancelled."""
        logger.info("AI tool detector started (scan_interval=%.0fs)", self._scan_interval)

        # Load policy lists if available
        for policy in self._agent.policies:
            rules = policy.get("rules", {})
            if "ai_tools_allow" in rules:
                self._allow_list = set(rules["ai_tools_allow"])
            if "ai_tools_block" in rules:
                self._block_list = set(rules["ai_tools_block"])

        try:
            while True:
                await self._full_scan()
                await asyncio.sleep(self._scan_interval)
        except asyncio.CancelledError:
            logger.info("AI tool detector stopping")
            raise

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_all_detected(self) -> List[Dict[str, Any]]:
        """Return all detected AI tools."""
        return [
            {
                "tool_name": d.signature.name,
                "vendor": d.signature.vendor,
                "category": d.signature.category,
                "detection_method": d.detection_method,
                "detail": d.detail,
                "allowed": d.allowed,
                "detected_at": d.detected_at,
            }
            for d in self._detected.values()
        ]

    def get_unauthorized(self) -> List[Dict[str, Any]]:
        """Return only unauthorized (blocked) AI tools."""
        return [t for t in self.get_all_detected() if not t["allowed"]]
