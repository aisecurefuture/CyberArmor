"""Process Monitor -- detects AI tool processes and suspicious command lines.

Uses ``psutil`` for cross-platform process enumeration.  Monitors running
processes for known AI tools (ChatGPT desktop, Claude desktop, GitHub Copilot,
Ollama, llama.cpp, etc.) and flags new launches matching configurable patterns.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

import psutil

if TYPE_CHECKING:
    from agent import EndpointAgent

logger = logging.getLogger("aishields.monitors.process")

# ---------------------------------------------------------------------------
# Known AI tool process patterns
# ---------------------------------------------------------------------------

# Map of descriptive name -> list of process-name regex patterns
KNOWN_AI_PROCESSES: Dict[str, List[str]] = {
    "ChatGPT Desktop": [r"(?i)chatgpt"],
    "Claude Desktop": [r"(?i)claude"],
    "GitHub Copilot": [r"(?i)copilot[\-_]?agent", r"(?i)copilot[\-_]?language[\-_]?server"],
    "Ollama": [r"(?i)^ollama$", r"(?i)ollama[\-_]?serve"],
    "llama.cpp": [r"(?i)llama[\-_]?server", r"(?i)llama[\.\-]cpp", r"(?i)^main\b.*\.gguf"],
    "LM Studio": [r"(?i)lm[\-_]?studio"],
    "Jan AI": [r"(?i)^jan$"],
    "LocalAI": [r"(?i)local[\-_]?ai"],
    "GPT4All": [r"(?i)gpt4all"],
    "Cursor AI": [r"(?i)cursor"],
    "Cody AI": [r"(?i)cody"],
    "Tabnine": [r"(?i)tabnine"],
    "Amazon CodeWhisperer": [r"(?i)codewhisperer"],
    "Replit AI": [r"(?i)replit"],
    "Hugging Face": [r"(?i)huggingface|(?i)transformers[\-_]?cli"],
    "Stable Diffusion": [r"(?i)stable[\-_]?diffusion|(?i)webui"],
    "ComfyUI": [r"(?i)comfyui"],
    "OpenClaw AI": [r"(?i)openclaw"],
    "Text Generation WebUI": [r"(?i)text[\-_]?generation[\-_]?webui"],
    "vLLM": [r"(?i)^vllm$"],
    "TensorRT-LLM": [r"(?i)tensorrt[\-_]?llm"],
}

# Suspicious command-line argument patterns
SUSPICIOUS_CMDLINE_PATTERNS: List[str] = [
    r"--model\s+\S+\.gguf",
    r"--model\s+\S+\.safetensors",
    r"openai\.api_key",
    r"ANTHROPIC_API_KEY",
    r"OPENAI_API_KEY",
    r"HF_TOKEN",
    r"huggingface\.co/",
    r"api\.openai\.com",
    r"api\.anthropic\.com",
    r"--serve\s+.*model",
    r"transformers.*pipeline",
    r"torch\.load",
    r"from_pretrained",
]


@dataclass
class ProcessInfo:
    """Snapshot of a running process."""

    pid: int
    name: str
    cmdline: str
    exe: Optional[str]
    username: Optional[str]
    create_time: float
    ai_tool_name: Optional[str] = None


@dataclass
class ProcessMonitorState:
    """Tracks previously-seen PIDs to detect new launches."""

    known_pids: Set[int] = field(default_factory=set)
    detected_ai_tools: Dict[int, ProcessInfo] = field(default_factory=dict)


class ProcessMonitor:
    """Monitors running processes for AI tool usage.

    Parameters
    ----------
    agent : EndpointAgent
        Parent agent instance used for telemetry reporting and config.
    poll_interval : float
        Seconds between process scans (default 5).
    """

    def __init__(
        self,
        agent: EndpointAgent,
        poll_interval: float = 5.0,
        extra_patterns: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        self._agent = agent
        self._poll_interval = poll_interval
        self._state = ProcessMonitorState()
        self._compiled_patterns: Dict[str, List[re.Pattern[str]]] = {}
        self._compiled_cmdline: List[re.Pattern[str]] = []

        # Merge default + extra patterns
        all_patterns = dict(KNOWN_AI_PROCESSES)
        if extra_patterns:
            for name, pats in extra_patterns.items():
                all_patterns.setdefault(name, []).extend(pats)

        for tool_name, patterns in all_patterns.items():
            self._compiled_patterns[tool_name] = [
                re.compile(p) for p in patterns
            ]

        for pat in SUSPICIOUS_CMDLINE_PATTERNS:
            self._compiled_cmdline.append(re.compile(pat))

    # ------------------------------------------------------------------
    # Process scanning
    # ------------------------------------------------------------------

    def _snapshot_processes(self) -> List[ProcessInfo]:
        """Return a snapshot of all currently-running processes."""
        procs: List[ProcessInfo] = []
        for proc in psutil.process_iter(["pid", "name", "cmdline", "exe", "username", "create_time"]):
            try:
                info = proc.info  # type: ignore[attr-defined]
                cmdline_list = info.get("cmdline") or []
                procs.append(
                    ProcessInfo(
                        pid=info["pid"],
                        name=info.get("name") or "",
                        cmdline=" ".join(cmdline_list),
                        exe=info.get("exe"),
                        username=info.get("username"),
                        create_time=info.get("create_time") or 0.0,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return procs

    def _match_ai_tool(self, proc: ProcessInfo) -> Optional[str]:
        """Return the AI tool name if the process matches, else None."""
        for tool_name, patterns in self._compiled_patterns.items():
            for pat in patterns:
                if pat.search(proc.name) or pat.search(proc.cmdline):
                    return tool_name
        return None

    def _check_suspicious_cmdline(self, proc: ProcessInfo) -> List[str]:
        """Return a list of suspicious pattern descriptions matched."""
        matches: List[str] = []
        for pat in self._compiled_cmdline:
            if pat.search(proc.cmdline):
                matches.append(pat.pattern)
        return matches

    # ------------------------------------------------------------------
    # Event generation
    # ------------------------------------------------------------------

    async def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Send a telemetry event through the parent agent."""
        event = {
            "source": "process_monitor",
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **data,
        }
        await self._agent.report_event(event)

    async def _handle_new_process(self, proc: ProcessInfo) -> None:
        """Evaluate a newly-seen process."""
        # Check for AI tool match
        tool_name = self._match_ai_tool(proc)
        if tool_name:
            proc.ai_tool_name = tool_name
            self._state.detected_ai_tools[proc.pid] = proc
            logger.warning(
                "AI tool detected: %s (pid=%d name=%s user=%s)",
                tool_name,
                proc.pid,
                proc.name,
                proc.username,
            )
            await self._emit_event(
                "ai_tool_process_detected",
                {
                    "tool_name": tool_name,
                    "pid": proc.pid,
                    "process_name": proc.name,
                    "exe": proc.exe,
                    "username": proc.username,
                    "cmdline_preview": proc.cmdline[:500],
                    "severity": "high",
                },
            )

        # Check for suspicious command-line patterns
        suspicious = self._check_suspicious_cmdline(proc)
        if suspicious:
            logger.warning(
                "Suspicious cmdline pid=%d name=%s patterns=%s",
                proc.pid,
                proc.name,
                suspicious,
            )
            await self._emit_event(
                "suspicious_cmdline_detected",
                {
                    "pid": proc.pid,
                    "process_name": proc.name,
                    "exe": proc.exe,
                    "username": proc.username,
                    "matched_patterns": suspicious,
                    "cmdline_preview": proc.cmdline[:500],
                    "severity": "medium",
                },
            )

    async def _handle_exited_process(self, pid: int) -> None:
        """Clean up state when a monitored AI tool process exits."""
        info = self._state.detected_ai_tools.pop(pid, None)
        if info:
            logger.info(
                "AI tool process exited: %s (pid=%d)", info.ai_tool_name, pid
            )
            await self._emit_event(
                "ai_tool_process_exited",
                {
                    "tool_name": info.ai_tool_name,
                    "pid": pid,
                    "process_name": info.name,
                    "severity": "info",
                },
            )

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Continuously monitor processes until cancelled."""
        logger.info("Process monitor started (poll_interval=%.1fs)", self._poll_interval)

        # Initial snapshot -- populate known PIDs without alerting
        initial = self._snapshot_processes()
        for proc in initial:
            self._state.known_pids.add(proc.pid)
            tool_name = self._match_ai_tool(proc)
            if tool_name:
                proc.ai_tool_name = tool_name
                self._state.detected_ai_tools[proc.pid] = proc
                logger.info(
                    "Pre-existing AI tool: %s (pid=%d)", tool_name, proc.pid
                )

        try:
            while True:
                await asyncio.sleep(self._poll_interval)
                await self._scan_cycle()
        except asyncio.CancelledError:
            logger.info("Process monitor stopping")
            raise

    async def _scan_cycle(self) -> None:
        """Execute a single scan cycle."""
        current_procs = self._snapshot_processes()
        current_pids = {p.pid for p in current_procs}

        # Detect new processes
        new_pids = current_pids - self._state.known_pids
        for proc in current_procs:
            if proc.pid in new_pids:
                await self._handle_new_process(proc)

        # Detect exited processes
        exited_pids = self._state.known_pids - current_pids
        for pid in exited_pids:
            await self._handle_exited_process(pid)

        self._state.known_pids = current_pids

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_detected_ai_tools(self) -> List[Dict[str, Any]]:
        """Return a list of currently-detected AI tool processes."""
        return [
            {
                "pid": info.pid,
                "tool_name": info.ai_tool_name,
                "process_name": info.name,
                "exe": info.exe,
                "username": info.username,
            }
            for info in self._state.detected_ai_tools.values()
        ]
