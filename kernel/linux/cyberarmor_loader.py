#!/usr/bin/env python3
"""
CyberArmor - eBPF Program Loader
Loads eBPF programs, populates configuration maps, and processes events.
"""

import ctypes
import ipaddress
import json
import logging
import os
import signal
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("cyberarmor.ebpf.loader")

# Event types matching the BPF program
EVENT_CONNECT = 1
EVENT_EXEC = 2
EVENT_FILE_OPEN = 3
EVENT_SENDTO = 4

EVENT_NAMES = {
    EVENT_CONNECT: "connect",
    EVENT_EXEC: "exec",
    EVENT_FILE_OPEN: "file_open",
    EVENT_SENDTO: "sendto",
}

ACTION_MONITOR = 0
ACTION_BLOCK = 1

# Known AI API endpoint IPs (resolved at load time)
AI_DOMAINS = [
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "api.cohere.ai", "api-inference.huggingface.co", "api.mistral.ai",
    "api.together.xyz", "api.replicate.com", "api.ai21.com",
    "api.stability.ai", "api.perplexity.ai", "api.groq.com",
]

# AI tool process names
AI_PROCESSES = [
    "chatgpt", "copilot", "claude", "ollama", "llamacpp",
    "text-generation", "vllm", "tritonserver", "tgi",
]

# Sensitive file paths to monitor
SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/root/.ssh/", "/home/*/.ssh/",
    "/etc/ssl/private/", "/etc/pki/tls/private/",
    "/var/lib/docker/", "/run/secrets/",
]

# Common AI API ports
AI_PORTS = [443, 8080, 8443, 11434]  # 11434 = Ollama


@dataclass
class BPFEvent:
    timestamp_ns: int
    pid: int
    tid: int
    uid: int
    event_type: int
    action: int
    comm: str
    details: dict


class CyberArmorEBPFLoader:
    def __init__(self, bpf_object_path: str, config_path: Optional[str] = None):
        self.bpf_object_path = bpf_object_path
        self.config_path = config_path
        self.running = False
        self._event_callbacks: List = []
        self._stats = {"connect": 0, "exec": 0, "file_open": 0, "sendto": 0}
        self._bpf = None
        self._config = self._load_config()

    def _load_config(self) -> dict:
        if self.config_path and os.path.exists(self.config_path):
            with open(self.config_path) as f:
                return json.load(f)
        return {
            "target_domains": AI_DOMAINS,
            "ai_processes": AI_PROCESSES,
            "sensitive_paths": SENSITIVE_PATHS,
            "target_ports": AI_PORTS,
            "control_plane_url": os.environ.get("CONTROL_PLANE_URL", ""),
            "api_key": os.environ.get("API_KEY", ""),
            "tenant_id": os.environ.get("TENANT_ID", ""),
            "large_payload_threshold": 4096,
        }

    def load(self):
        """Load and attach eBPF programs."""
        try:
            from bcc import BPF, lib as bpf_lib
            logger.info("Using BCC for eBPF loading")
            return self._load_with_bcc()
        except ImportError:
            pass

        try:
            import libbpf
            logger.info("Using libbpf for eBPF loading")
            return self._load_with_libbpf()
        except ImportError:
            pass

        logger.error(
            "Neither BCC nor libbpf available. Install with: "
            "apt install bpfcc-tools python3-bpfcc or pip install libbpf"
        )
        sys.exit(1)

    def _load_with_bcc(self):
        """Load using BCC (BPF Compiler Collection)."""
        from bcc import BPF

        # Read and compile the BPF C source
        src_path = self.bpf_object_path.replace(".bpf.o", ".bpf.c")
        if os.path.exists(src_path):
            self._bpf = BPF(src_file=src_path)
        else:
            logger.error(f"BPF source not found: {src_path}")
            sys.exit(1)

        # Populate maps
        self._populate_target_ips()
        self._populate_target_ports()
        self._populate_ai_processes()
        self._populate_sensitive_paths()

        logger.info("eBPF programs loaded and attached via BCC")

    def _load_with_libbpf(self):
        """Load using libbpf (precompiled .bpf.o)."""
        # libbpf-based loading for precompiled CO-RE objects
        logger.info(f"Loading BPF object: {self.bpf_object_path}")
        # Implementation depends on specific libbpf Python bindings
        raise NotImplementedError("libbpf loading - use BCC for development")

    def _populate_target_ips(self):
        """Resolve AI domain names and populate target_ips map."""
        import socket

        target_ips = self._bpf["target_ips"]
        for domain in self._config.get("target_domains", []):
            try:
                ips = socket.getaddrinfo(domain, None, socket.AF_INET)
                for _, _, _, _, (ip, _) in ips:
                    packed = struct.unpack("!I", socket.inet_aton(ip))[0]
                    key = ctypes.c_uint32(packed)
                    val = ctypes.c_uint8(ACTION_MONITOR)
                    target_ips[key] = val
                    logger.debug(f"Added target IP: {ip} ({domain})")
            except socket.gaierror:
                logger.warning(f"Cannot resolve: {domain}")

    def _populate_target_ports(self):
        """Populate target_ports map."""
        target_ports = self._bpf["target_ports"]
        for port in self._config.get("target_ports", []):
            key = ctypes.c_uint16(port)
            val = ctypes.c_uint8(ACTION_MONITOR)
            target_ports[key] = val

    def _populate_ai_processes(self):
        """Populate ai_processes map."""
        ai_procs = self._bpf["ai_processes"]
        for proc in self._config.get("ai_processes", []):
            key = proc.encode().ljust(64, b"\x00")
            val = ctypes.c_uint8(ACTION_MONITOR)
            ai_procs[ctypes.create_string_buffer(key, 64)] = val

    def _populate_sensitive_paths(self):
        """Populate sensitive_paths map."""
        sensitive = self._bpf["sensitive_paths"]
        for path in self._config.get("sensitive_paths", []):
            if "*" in path:
                continue  # Wildcards not supported in hash maps
            key = path.encode().ljust(256, b"\x00")
            val = ctypes.c_uint8(ACTION_MONITOR)
            sensitive[ctypes.create_string_buffer(key, 256)] = val

    def on_event(self, callback):
        """Register event callback."""
        self._event_callbacks.append(callback)

    def _handle_event(self, ctx, data, size):
        """Process events from ring buffer."""
        # Parse event structure
        event_data = ctypes.string_at(data, size)
        if len(event_data) < 88:  # minimum event size
            return

        ts_ns = struct.unpack_from("Q", event_data, 0)[0]
        pid = struct.unpack_from("I", event_data, 8)[0]
        tid = struct.unpack_from("I", event_data, 12)[0]
        uid = struct.unpack_from("I", event_data, 16)[0]
        event_type = struct.unpack_from("I", event_data, 20)[0]
        action = struct.unpack_from("I", event_data, 24)[0]
        comm = event_data[32:96].split(b"\x00")[0].decode("utf-8", errors="replace")

        details = {}
        if event_type == EVENT_CONNECT:
            dst_addr = struct.unpack_from("I", event_data, 96)[0]
            dst_port = struct.unpack_from("H", event_data, 100)[0]
            dst_ip = str(ipaddress.IPv4Address(struct.pack("!I", dst_addr)))
            details = {"dst_ip": dst_ip, "dst_port": dst_port}
        elif event_type == EVENT_EXEC:
            filename = event_data[96:352].split(b"\x00")[0].decode("utf-8", errors="replace")
            details = {"filename": filename}
        elif event_type == EVENT_FILE_OPEN:
            path = event_data[96:352].split(b"\x00")[0].decode("utf-8", errors="replace")
            flags = struct.unpack_from("I", event_data, 352)[0]
            details = {"path": path, "flags": flags}
        elif event_type == EVENT_SENDTO:
            dst_addr = struct.unpack_from("I", event_data, 96)[0]
            dst_port = struct.unpack_from("H", event_data, 100)[0]
            send_size = struct.unpack_from("I", event_data, 104)[0]
            dst_ip = str(ipaddress.IPv4Address(struct.pack("!I", dst_addr)))
            details = {"dst_ip": dst_ip, "dst_port": dst_port, "size": send_size}

        event = BPFEvent(
            timestamp_ns=ts_ns, pid=pid, tid=tid, uid=uid,
            event_type=event_type, action=action, comm=comm, details=details,
        )

        event_name = EVENT_NAMES.get(event_type, "unknown")
        self._stats[event_name] = self._stats.get(event_name, 0) + 1

        logger.info(
            f"[{event_name}] pid={pid} comm={comm} action={'BLOCK' if action else 'MONITOR'} {details}"
        )

        for cb in self._event_callbacks:
            try:
                cb(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}")

    def run(self):
        """Main event loop."""
        if not self._bpf:
            logger.error("BPF not loaded. Call load() first.")
            return

        self.running = True

        # Set up signal handlers
        def handle_signal(signum, frame):
            logger.info(f"Received signal {signum}, shutting down...")
            self.running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        # Open ring buffer
        self._bpf["events"].open_ring_buffer(self._handle_event)

        logger.info("CyberArmor eBPF monitor running. Press Ctrl+C to stop.")
        while self.running:
            try:
                self._bpf.ring_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break

        self.cleanup()

    def cleanup(self):
        """Clean up eBPF resources."""
        logger.info(f"eBPF monitor stopped. Stats: {self._stats}")
        self.running = False

    def get_stats(self) -> dict:
        return dict(self._stats)


def forward_to_control_plane(event: BPFEvent, url: str, api_key: str, tenant_id: str):
    """Forward eBPF events to the CyberArmor control plane."""
    import requests

    try:
        requests.post(
            f"{url}/api/v1/telemetry",
            json={
                "tenant_id": tenant_id,
                "source": "ebpf_monitor",
                "event_type": EVENT_NAMES.get(event.event_type, "unknown"),
                "severity": "high" if event.action == ACTION_BLOCK else "medium",
                "pid": event.pid,
                "uid": event.uid,
                "process": event.comm,
                "details": event.details,
                "timestamp": time.time(),
            },
            headers={"x-api-key": api_key, "Content-Type": "application/json"},
            timeout=5,
        )
    except Exception as e:
        logger.warning(f"Failed to forward event: {e}")


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    bpf_src = str(Path(__file__).parent / "cyberarmor_monitor.bpf.c")
    config_path = os.environ.get("CYBERARMOR_CONFIG", None)

    loader = CyberArmorEBPFLoader(bpf_src, config_path)

    # Set up control plane forwarding
    cp_url = os.environ.get("CONTROL_PLANE_URL", "")
    api_key = os.environ.get("API_KEY", "")
    tenant_id = os.environ.get("TENANT_ID", "")
    if cp_url and api_key:
        loader.on_event(lambda e: forward_to_control_plane(e, cp_url, api_key, tenant_id))

    loader.load()
    loader.run()


if __name__ == "__main__":
    main()
