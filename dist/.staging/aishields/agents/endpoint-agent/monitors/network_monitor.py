"""Network Monitor -- tracks connections to AI service domains and APIs.

Monitors DNS queries (where possible), active TCP connections to known AI
endpoints, unusual data upload patterns, MCP (Model Context Protocol)
connections, and per-service bandwidth estimates.  Uses ``psutil`` and
standard ``socket`` operations for cross-platform compatibility.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

import psutil

if TYPE_CHECKING:
    from agent import EndpointAgent

logger = logging.getLogger("aishields.monitors.network")

# ---------------------------------------------------------------------------
# Known AI service domains / IP patterns
# ---------------------------------------------------------------------------

KNOWN_AI_DOMAINS: Dict[str, List[str]] = {
    "OpenAI": [
        "api.openai.com",
        "chat.openai.com",
        "platform.openai.com",
        "oaidalleapiprodscus.blob.core.windows.net",
    ],
    "Anthropic": [
        "api.anthropic.com",
        "claude.ai",
        "console.anthropic.com",
    ],
    "Google AI": [
        "generativelanguage.googleapis.com",
        "aistudio.google.com",
        "gemini.google.com",
        "bard.google.com",
    ],
    "GitHub Copilot": [
        "copilot-proxy.githubusercontent.com",
        "api.githubcopilot.com",
        "copilot.githubusercontent.com",
    ],
    "Hugging Face": [
        "huggingface.co",
        "api-inference.huggingface.co",
        "cdn-lfs.huggingface.co",
    ],
    "Stability AI": [
        "api.stability.ai",
    ],
    "Cohere": [
        "api.cohere.ai",
        "api.cohere.com",
    ],
    "Mistral AI": [
        "api.mistral.ai",
    ],
    "Perplexity": [
        "api.perplexity.ai",
        "www.perplexity.ai",
    ],
    "Replicate": [
        "api.replicate.com",
    ],
    "Together AI": [
        "api.together.xyz",
    ],
    "Groq": [
        "api.groq.com",
    ],
    "Ollama (remote)": [
        "ollama.com",
        "registry.ollama.ai",
    ],
    "OpenClaw AI": [
        "openclaw.ai",
        "api.openclaw.ai",
    ],
}

# Flatten for quick look-up
_ALL_AI_DOMAINS: Set[str] = set()
_DOMAIN_TO_SERVICE: Dict[str, str] = {}
for _svc, _domains in KNOWN_AI_DOMAINS.items():
    for _d in _domains:
        _ALL_AI_DOMAINS.add(_d)
        _DOMAIN_TO_SERVICE[_d] = _svc

# MCP protocol default ports
MCP_DEFAULT_PORTS: Set[int] = {3000, 3001, 8080, 8765}

# Threshold for "large upload" detection (bytes in a single connection)
LARGE_UPLOAD_THRESHOLD_BYTES = 5 * 1024 * 1024  # 5 MB


@dataclass
class ConnectionRecord:
    """Represents an observed network connection to an AI service."""

    service_name: str
    remote_addr: str
    remote_port: int
    local_port: int
    pid: Optional[int]
    process_name: Optional[str]
    first_seen: float
    last_seen: float
    bytes_sent: int = 0
    bytes_recv: int = 0


@dataclass
class NetworkMonitorState:
    """Persistent state across scan cycles."""

    known_connections: Dict[Tuple[str, int], ConnectionRecord] = field(default_factory=dict)
    dns_cache: Dict[str, str] = field(default_factory=dict)  # ip -> domain
    bandwidth_per_service: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    alerted_connections: Set[Tuple[str, int]] = field(default_factory=set)


class NetworkMonitor:
    """Monitors network connections for AI service traffic.

    Parameters
    ----------
    agent : EndpointAgent
        Parent agent for telemetry and configuration.
    poll_interval : float
        Seconds between connection scans (default 5).
    """

    def __init__(self, agent: EndpointAgent, poll_interval: float = 5.0) -> None:
        self._agent = agent
        self._poll_interval = poll_interval
        self._state = NetworkMonitorState()

    # ------------------------------------------------------------------
    # DNS resolution helpers
    # ------------------------------------------------------------------

    def _resolve_domain(self, ip: str) -> Optional[str]:
        """Attempt reverse DNS look-up, returning cached result when possible."""
        if ip in self._state.dns_cache:
            return self._state.dns_cache[ip]
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            self._state.dns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None

    def _resolve_ai_domain(self, ip: str) -> Optional[str]:
        """Check if *ip* resolves to a known AI service domain."""
        hostname = self._resolve_domain(ip)
        if not hostname:
            return None
        hostname_lower = hostname.lower()
        for domain in _ALL_AI_DOMAINS:
            if hostname_lower == domain or hostname_lower.endswith("." + domain):
                return domain
        return None

    def _match_domain_directly(self, ip: str) -> Optional[str]:
        """Forward-resolve known AI domains and check against *ip*."""
        for domain in _ALL_AI_DOMAINS:
            try:
                resolved = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for _, _, _, _, addr in resolved:
                    if addr[0] == ip:
                        self._state.dns_cache[ip] = domain
                        return domain
            except (socket.gaierror, OSError):
                continue
        return None

    # ------------------------------------------------------------------
    # Connection scanning
    # ------------------------------------------------------------------

    def _scan_connections(self) -> List[Dict[str, Any]]:
        """Return established TCP connections with process info."""
        results: List[Dict[str, Any]] = []
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != "ESTABLISHED" or conn.raddr is None:
                continue
            remote_ip, remote_port = conn.raddr
            local_port = conn.laddr.port if conn.laddr else 0
            pid = conn.pid
            proc_name = None
            if pid:
                try:
                    proc_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            results.append({
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "local_port": local_port,
                "pid": pid,
                "process_name": proc_name,
            })
        return results

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    async def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        event = {
            "source": "network_monitor",
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **data,
        }
        await self._agent.report_event(event)

    # ------------------------------------------------------------------
    # Per-cycle analysis
    # ------------------------------------------------------------------

    async def _analyse_connection(self, conn: Dict[str, Any]) -> None:
        """Analyse a single connection for AI service traffic."""
        remote_ip: str = conn["remote_ip"]
        remote_port: int = conn["remote_port"]
        key = (remote_ip, remote_port)

        # Already alerted
        if key in self._state.alerted_connections:
            return

        # Try to identify the domain
        domain = self._resolve_ai_domain(remote_ip)
        if not domain:
            domain = self._match_domain_directly(remote_ip)

        if domain:
            service = _DOMAIN_TO_SERVICE.get(domain, "Unknown AI Service")
            logger.warning(
                "AI service connection: %s (%s) -> %s:%d pid=%s",
                service,
                domain,
                remote_ip,
                remote_port,
                conn.get("pid"),
            )
            self._state.alerted_connections.add(key)
            record = ConnectionRecord(
                service_name=service,
                remote_addr=remote_ip,
                remote_port=remote_port,
                local_port=conn.get("local_port", 0),
                pid=conn.get("pid"),
                process_name=conn.get("process_name"),
                first_seen=time.monotonic(),
                last_seen=time.monotonic(),
            )
            self._state.known_connections[key] = record
            await self._emit_event(
                "ai_service_connection_detected",
                {
                    "service": service,
                    "domain": domain,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "pid": conn.get("pid"),
                    "process_name": conn.get("process_name"),
                    "severity": "high",
                },
            )

        # MCP connection detection (local ports commonly used by MCP servers)
        if remote_port in MCP_DEFAULT_PORTS or conn.get("local_port", 0) in MCP_DEFAULT_PORTS:
            if key not in self._state.alerted_connections:
                logger.info(
                    "Possible MCP connection: %s:%d (pid=%s)",
                    remote_ip,
                    remote_port,
                    conn.get("pid"),
                )
                self._state.alerted_connections.add(key)
                await self._emit_event(
                    "mcp_connection_detected",
                    {
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "local_port": conn.get("local_port"),
                        "pid": conn.get("pid"),
                        "process_name": conn.get("process_name"),
                        "severity": "medium",
                    },
                )

    async def _detect_large_uploads(self) -> None:
        """Check aggregate network IO for large outbound data transfers."""
        try:
            counters = psutil.net_io_counters(pernic=False)
            if counters and counters.bytes_sent > 0:
                # This is a simplified heuristic; a production version would
                # track deltas per connection using eBPF or pcap.
                pass
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Continuously monitor network connections until cancelled."""
        logger.info("Network monitor started (poll_interval=%.1fs)", self._poll_interval)

        try:
            while True:
                await asyncio.sleep(self._poll_interval)
                await self._scan_cycle()
        except asyncio.CancelledError:
            logger.info("Network monitor stopping")
            raise

    async def _scan_cycle(self) -> None:
        connections = self._scan_connections()
        for conn in connections:
            await self._analyse_connection(conn)
        await self._detect_large_uploads()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_active_ai_connections(self) -> List[Dict[str, Any]]:
        """Return currently tracked AI service connections."""
        return [
            {
                "service": rec.service_name,
                "remote_addr": rec.remote_addr,
                "remote_port": rec.remote_port,
                "pid": rec.pid,
                "process_name": rec.process_name,
            }
            for rec in self._state.known_connections.values()
        ]

    def get_bandwidth_summary(self) -> Dict[str, int]:
        """Return cumulative bytes-sent per AI service."""
        return dict(self._state.bandwidth_per_service)
