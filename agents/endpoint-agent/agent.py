"""AIShields Endpoint Agent - Cross-platform system service daemon.

Runs as a system service/daemon on macOS, Windows, and Linux.  On startup the
agent registers with the control plane, begins periodic policy synchronisation,
and launches concurrent monitor threads for process, file-system, network, and
AI-tool detection.  All telemetry is forwarded to the control plane over an
authenticated HTTPS channel (``x-api-key`` header).

Environment variables
---------------------
CONTROL_PLANE_URL : str
    Base URL of the AIShields control plane (default ``https://localhost:8000``).
AGENT_API_KEY : str
    API key used to authenticate with the control plane.
TENANT_ID : str
    Tenant identifier the agent belongs to.
AGENT_ID : str
    Unique agent identifier (auto-generated UUID4 if not set).

Configuration files
-------------------
* macOS / Linux: ``/etc/aishields/agent.conf``
* Windows: ``%PROGRAMDATA%\\AIShields\\agent.conf``
"""

from __future__ import annotations

import asyncio
import configparser
import json
import logging
import os
import platform
import signal
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("aishields.endpoint_agent")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AGENT_VERSION = "1.0.0"
HEARTBEAT_INTERVAL_SECONDS = 30
POLICY_SYNC_INTERVAL_SECONDS = 300
TELEMETRY_FLUSH_INTERVAL_SECONDS = 10
DEFAULT_CONTROL_PLANE_URL = "https://localhost:8000"

# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------


def _config_path() -> Path:
    """Return the platform-appropriate configuration file path."""
    system = platform.system()
    if system == "Windows":
        program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        return Path(program_data) / "AIShields" / "agent.conf"
    return Path("/etc/aishields/agent.conf")


def _load_config(path: Optional[Path] = None) -> configparser.ConfigParser:
    """Load agent configuration, falling back to sensible defaults."""
    cfg = configparser.ConfigParser()
    # Defaults
    cfg["agent"] = {
        "control_plane_url": DEFAULT_CONTROL_PLANE_URL,
        "agent_api_key": "",
        "tenant_id": "",
        "agent_id": str(uuid.uuid4()),
        "heartbeat_interval": str(HEARTBEAT_INTERVAL_SECONDS),
        "policy_sync_interval": str(POLICY_SYNC_INTERVAL_SECONDS),
        "telemetry_flush_interval": str(TELEMETRY_FLUSH_INTERVAL_SECONDS),
        "log_level": "INFO",
    }
    cfg["monitors"] = {
        "process_enabled": "true",
        "file_enabled": "true",
        "network_enabled": "true",
        "ai_tool_enabled": "true",
    }
    cfg["dlp"] = {
        "enabled": "true",
        "scan_clipboard": "true",
    }
    cfg["zero_day"] = {
        "rce_guard_enabled": "true",
        "sandbox_enabled": "false",
    }

    config_file = path or _config_path()
    if config_file.exists():
        logger.info("Loading configuration from %s", config_file)
        cfg.read(str(config_file))
    else:
        logger.info("No config file at %s; using defaults + env vars", config_file)

    return cfg


def _env_override(cfg: configparser.ConfigParser) -> Dict[str, str]:
    """Override config values with environment variables where set."""
    overrides: Dict[str, str] = {}
    mapping = {
        "CONTROL_PLANE_URL": ("agent", "control_plane_url"),
        "AGENT_API_KEY": ("agent", "agent_api_key"),
        "TENANT_ID": ("agent", "tenant_id"),
        "AGENT_ID": ("agent", "agent_id"),
    }
    for env_var, (section, key) in mapping.items():
        value = os.environ.get(env_var)
        if value:
            cfg.set(section, key, value)
            overrides[env_var] = value
    return overrides


# ---------------------------------------------------------------------------
# Telemetry buffer
# ---------------------------------------------------------------------------


class TelemetryBuffer:
    """Thread-safe telemetry event buffer that flushes to the control plane."""

    def __init__(self, max_size: int = 500) -> None:
        self._buffer: List[Dict[str, Any]] = []
        self._max_size = max_size
        self._lock = asyncio.Lock()

    async def add(self, event: Dict[str, Any]) -> None:
        """Append an event, dropping the oldest if the buffer is full."""
        async with self._lock:
            if len(self._buffer) >= self._max_size:
                self._buffer.pop(0)
            self._buffer.append(event)

    async def drain(self) -> List[Dict[str, Any]]:
        """Remove and return all buffered events."""
        async with self._lock:
            events = list(self._buffer)
            self._buffer.clear()
            return events

    @property
    def size(self) -> int:
        return len(self._buffer)


# ---------------------------------------------------------------------------
# Main Agent class
# ---------------------------------------------------------------------------


class EndpointAgent:
    """AIShields cross-platform endpoint agent daemon.

    Lifecycle
    ---------
    1. ``__init__`` -- load config, prepare HTTP client.
    2. ``start()`` -- register with control plane, start monitors, enter run loop.
    3. ``stop()`` -- graceful shutdown of all monitors and the event loop.
    """

    def __init__(self, config_path: Optional[Path] = None) -> None:
        self._cfg = _load_config(config_path)
        _env_override(self._cfg)

        # Core settings
        self.control_plane_url: str = self._cfg.get("agent", "control_plane_url")
        self.api_key: str = self._cfg.get("agent", "agent_api_key")
        self.tenant_id: str = self._cfg.get("agent", "tenant_id")
        self.agent_id: str = self._cfg.get("agent", "agent_id")
        self.heartbeat_interval: int = self._cfg.getint(
            "agent", "heartbeat_interval", fallback=HEARTBEAT_INTERVAL_SECONDS
        )
        self.policy_sync_interval: int = self._cfg.getint(
            "agent", "policy_sync_interval", fallback=POLICY_SYNC_INTERVAL_SECONDS
        )
        self.telemetry_flush_interval: int = self._cfg.getint(
            "agent", "telemetry_flush_interval", fallback=TELEMETRY_FLUSH_INTERVAL_SECONDS
        )

        # Logging
        log_level = self._cfg.get("agent", "log_level", fallback="INFO").upper()
        logging.getLogger().setLevel(getattr(logging, log_level, logging.INFO))

        # Runtime state
        self._running = False
        self._telemetry = TelemetryBuffer()
        self._policies: List[Dict[str, Any]] = []
        self._http_client: Optional[httpx.AsyncClient] = None
        self._monitor_tasks: List[asyncio.Task] = []  # type: ignore[type-arg]
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Platform info (sent during registration)
        self._platform_info = {
            "os": platform.system(),
            "os_version": platform.version(),
            "hostname": platform.node(),
            "arch": platform.machine(),
            "python_version": platform.python_version(),
        }

        logger.info(
            "Agent initialised  agent_id=%s tenant_id=%s control_plane=%s",
            self.agent_id,
            self.tenant_id,
            self.control_plane_url,
        )

    # -- HTTP helpers -------------------------------------------------------

    def _auth_headers(self) -> Dict[str, str]:
        return {"x-api-key": self.api_key, "Content-Type": "application/json"}

    async def _ensure_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(15.0, connect=5.0),
                headers=self._auth_headers(),
                verify=True,
            )
        return self._http_client

    # -- Control-plane communication ----------------------------------------

    async def _register(self) -> bool:
        """Register or re-register this agent with the control plane."""
        payload = {
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "agent_version": AGENT_VERSION,
            "platform": self._platform_info,
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            client = await self._ensure_http_client()
            resp = await client.post(
                f"{self.control_plane_url}/agents/register",
                json=payload,
            )
            if resp.status_code in (200, 201):
                logger.info("Registered with control plane (status=%s)", resp.status_code)
                return True
            logger.warning(
                "Registration failed status=%s body=%s", resp.status_code, resp.text[:200]
            )
        except Exception as exc:
            logger.error("Registration error: %s", exc)
        return False

    async def _heartbeat(self) -> None:
        """Send a single heartbeat to the control plane."""
        payload = {
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "running",
            "telemetry_buffer_size": self._telemetry.size,
            "active_monitors": len(self._monitor_tasks),
            "uptime_seconds": int(time.monotonic() - self._start_time),
        }
        try:
            client = await self._ensure_http_client()
            resp = await client.post(
                f"{self.control_plane_url}/agents/{self.agent_id}/heartbeat",
                json=payload,
            )
            if resp.status_code not in (200, 204):
                logger.warning("Heartbeat non-OK status=%s", resp.status_code)
        except Exception as exc:
            logger.debug("Heartbeat failed: %s", exc)

    async def _sync_policies(self) -> None:
        """Fetch the latest policies from the control plane."""
        try:
            client = await self._ensure_http_client()
            resp = await client.get(
                f"{self.control_plane_url}/policies/{self.tenant_id}",
            )
            if resp.status_code == 200:
                self._policies = resp.json()
                logger.info("Policy sync complete: %d policies", len(self._policies))
                # Notify policy enforcer
                try:
                    from policy_enforcer import PolicyEnforcer

                    enforcer = PolicyEnforcer.instance()
                    if enforcer:
                        enforcer.update_policies(self._policies)
                except ImportError:
                    pass
            else:
                logger.warning("Policy sync failed status=%s", resp.status_code)
        except Exception as exc:
            logger.error("Policy sync error: %s", exc)

    async def _flush_telemetry(self) -> None:
        """Drain buffered telemetry events and POST them to the control plane."""
        events = await self._telemetry.drain()
        if not events:
            return
        try:
            client = await self._ensure_http_client()
            resp = await client.post(
                f"{self.control_plane_url}/agents/{self.agent_id}/telemetry",
                json={"agent_id": self.agent_id, "events": events},
            )
            if resp.status_code not in (200, 202):
                logger.warning(
                    "Telemetry flush non-OK status=%s (events lost=%d)",
                    resp.status_code,
                    len(events),
                )
        except Exception as exc:
            logger.error("Telemetry flush error: %s (events lost=%d)", exc, len(events))

    # -- Public telemetry API -----------------------------------------------

    async def report_event(self, event: Dict[str, Any]) -> None:
        """Add a telemetry event to the outbound buffer.

        Parameters
        ----------
        event : dict
            Arbitrary event payload.  A ``timestamp`` field will be injected
            automatically if not present.
        """
        if "timestamp" not in event:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()
        event.setdefault("agent_id", self.agent_id)
        event.setdefault("tenant_id", self.tenant_id)
        await self._telemetry.add(event)

    # -- Monitor lifecycle --------------------------------------------------

    async def _start_monitors(self) -> None:
        """Launch all configured monitor coroutines as asyncio tasks."""
        monitors_cfg = self._cfg["monitors"]

        if monitors_cfg.getboolean("process_enabled", fallback=True):
            try:
                from monitors.process_monitor import ProcessMonitor

                monitor = ProcessMonitor(self)
                task = asyncio.create_task(monitor.run(), name="process_monitor")
                self._monitor_tasks.append(task)
                logger.info("Started process monitor")
            except Exception as exc:
                logger.error("Failed to start process monitor: %s", exc)

        if monitors_cfg.getboolean("file_enabled", fallback=True):
            try:
                from monitors.file_monitor import FileMonitor

                monitor = FileMonitor(self)
                task = asyncio.create_task(monitor.run(), name="file_monitor")
                self._monitor_tasks.append(task)
                logger.info("Started file monitor")
            except Exception as exc:
                logger.error("Failed to start file monitor: %s", exc)

        if monitors_cfg.getboolean("network_enabled", fallback=True):
            try:
                from monitors.network_monitor import NetworkMonitor

                monitor = NetworkMonitor(self)
                task = asyncio.create_task(monitor.run(), name="network_monitor")
                self._monitor_tasks.append(task)
                logger.info("Started network monitor")
            except Exception as exc:
                logger.error("Failed to start network monitor: %s", exc)

        if monitors_cfg.getboolean("ai_tool_enabled", fallback=True):
            try:
                from monitors.ai_tool_detector import AIToolDetector

                detector = AIToolDetector(self)
                task = asyncio.create_task(detector.run(), name="ai_tool_detector")
                self._monitor_tasks.append(task)
                logger.info("Started AI tool detector")
            except Exception as exc:
                logger.error("Failed to start AI tool detector: %s", exc)

    async def _stop_monitors(self) -> None:
        """Cancel all running monitor tasks and wait for them to finish."""
        for task in self._monitor_tasks:
            task.cancel()
        results = await asyncio.gather(*self._monitor_tasks, return_exceptions=True)
        for task, result in zip(self._monitor_tasks, results):
            if isinstance(result, Exception) and not isinstance(result, asyncio.CancelledError):
                logger.error("Monitor %s exited with error: %s", task.get_name(), result)
        self._monitor_tasks.clear()
        logger.info("All monitors stopped")

    # -- Background loops ---------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        """Periodically send heartbeats."""
        while self._running:
            await self._heartbeat()
            await asyncio.sleep(self.heartbeat_interval)

    async def _policy_sync_loop(self) -> None:
        """Periodically synchronise policies."""
        while self._running:
            await self._sync_policies()
            await asyncio.sleep(self.policy_sync_interval)

    async def _telemetry_loop(self) -> None:
        """Periodically flush telemetry events."""
        while self._running:
            await asyncio.sleep(self.telemetry_flush_interval)
            await self._flush_telemetry()

    # -- Lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        """Start the agent: register, sync policies, launch monitors."""
        self._running = True
        self._start_time = time.monotonic()
        self._loop = asyncio.get_running_loop()

        logger.info(
            "Starting AIShields Endpoint Agent v%s  agent_id=%s",
            AGENT_VERSION,
            self.agent_id,
        )

        # Register with control plane (retry up to 5 times)
        registered = False
        for attempt in range(1, 6):
            registered = await self._register()
            if registered:
                break
            wait = min(2 ** attempt, 30)
            logger.warning("Registration attempt %d failed; retrying in %ds", attempt, wait)
            await asyncio.sleep(wait)

        if not registered:
            logger.warning(
                "Could not register with control plane; continuing in offline mode"
            )

        # Initial policy sync
        await self._sync_policies()

        # Launch monitors
        await self._start_monitors()

        # Background maintenance tasks
        self._monitor_tasks.append(
            asyncio.create_task(self._heartbeat_loop(), name="heartbeat")
        )
        self._monitor_tasks.append(
            asyncio.create_task(self._policy_sync_loop(), name="policy_sync")
        )
        self._monitor_tasks.append(
            asyncio.create_task(self._telemetry_loop(), name="telemetry_flush")
        )

        logger.info("Agent fully started with %d tasks", len(self._monitor_tasks))

        # Block until shutdown is requested
        try:
            while self._running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Gracefully shut down the agent."""
        if not self._running:
            return
        self._running = False
        logger.info("Shutting down agent ...")

        # Final telemetry flush
        await self._flush_telemetry()

        # Stop monitors
        await self._stop_monitors()

        # Close HTTP client
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()

        logger.info("Agent stopped")

    def request_shutdown(self) -> None:
        """Signal the agent to stop from a synchronous context (signal handler)."""
        self._running = False
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)

    # -- Accessors ----------------------------------------------------------

    @property
    def policies(self) -> List[Dict[str, Any]]:
        """Return the currently loaded policies."""
        return list(self._policies)

    @property
    def config(self) -> configparser.ConfigParser:
        return self._cfg


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------


def _install_signal_handlers(agent: EndpointAgent) -> None:
    """Install OS signal handlers for graceful shutdown."""
    if platform.system() == "Windows":
        # Windows does not support SIGHUP
        signal.signal(signal.SIGINT, lambda *_: agent.request_shutdown())
        signal.signal(signal.SIGTERM, lambda *_: agent.request_shutdown())
    else:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            loop.add_signal_handler(sig, agent.request_shutdown)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def _async_main(config_path: Optional[Path] = None) -> None:
    agent = EndpointAgent(config_path=config_path)
    _install_signal_handlers(agent)
    await agent.start()


def main() -> None:
    """CLI entry point for the endpoint agent."""
    import argparse

    parser = argparse.ArgumentParser(description="AIShields Endpoint Agent")
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to agent.conf (default: platform-specific)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"aishields-endpoint-agent {AGENT_VERSION}",
    )
    args = parser.parse_args()

    try:
        asyncio.run(_async_main(config_path=args.config))
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception:
        logger.exception("Fatal error in endpoint agent")
        sys.exit(1)


if __name__ == "__main__":
    main()
