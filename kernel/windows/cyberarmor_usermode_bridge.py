#!/usr/bin/env python3
"""CyberArmor Windows minifilter usermode bridge.

Connects to the CyberArmor minifilter communication port, receives kernel
telemetry events, and forwards them to:
- Windows Event Log (Application log)
- CyberArmor control plane telemetry ingest

Configuration is environment-driven so this can run as a Windows service,
scheduled task, or a standalone process.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import argparse
import json
import logging
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Optional, Set


# ---------------------------------------------------------------------------
# Native constants / structures
# ---------------------------------------------------------------------------

S_OK = 0
INVALID_HANDLE_VALUE = wt.HANDLE(-1).value

EVENTLOG_ERROR_TYPE = 0x0001
EVENTLOG_WARNING_TYPE = 0x0002
EVENTLOG_INFORMATION_TYPE = 0x0004


class CYBERARMOR_FILE_CREATE(ctypes.Structure):
    _fields_ = [
        ("FilePath", wt.WCHAR * 520),
        ("DesiredAccess", wt.DWORD),
        ("CreateDisposition", wt.DWORD),
        ("IsDirectory", wt.BOOLEAN),
    ]


class CYBERARMOR_FILE_WRITE(ctypes.Structure):
    _fields_ = [
        ("FilePath", wt.WCHAR * 520),
        ("WriteLength", wt.DWORD),
    ]


class CYBERARMOR_FILE_DELETE(ctypes.Structure):
    _fields_ = [("FilePath", wt.WCHAR * 520)]


class CYBERARMOR_PROCESS_CREATE(ctypes.Structure):
    _fields_ = [
        ("ChildProcessId", wt.DWORD),
        ("ImageFileName", wt.WCHAR * 520),
        ("CommandLine", wt.WCHAR * 520),
    ]


class CYBERARMOR_PROCESS_TERMINATE(ctypes.Structure):
    _fields_ = [("ExitCode", wt.DWORD)]


class CYBERARMOR_NETWORK_CONNECT(ctypes.Structure):
    _fields_ = [
        ("RemoteAddress", wt.DWORD),
        ("RemotePort", wt.USHORT),
        ("LocalPort", wt.USHORT),
        ("Protocol", wt.USHORT),
    ]


class CYBERARMOR_EVENT_DATA(ctypes.Union):
    _fields_ = [
        ("FileCreate", CYBERARMOR_FILE_CREATE),
        ("FileWrite", CYBERARMOR_FILE_WRITE),
        ("FileDelete", CYBERARMOR_FILE_DELETE),
        ("ProcessCreate", CYBERARMOR_PROCESS_CREATE),
        ("ProcessTerminate", CYBERARMOR_PROCESS_TERMINATE),
        ("NetworkConnect", CYBERARMOR_NETWORK_CONNECT),
    ]


class CYBERARMOR_EVENT(ctypes.Structure):
    _fields_ = [
        ("EventType", wt.DWORD),
        ("Severity", wt.DWORD),
        ("Action", wt.DWORD),
        ("Timestamp", ctypes.c_longlong),
        ("ProcessId", wt.DWORD),
        ("ThreadId", wt.DWORD),
        ("ProcessName", wt.WCHAR * 260),
        ("Data", CYBERARMOR_EVENT_DATA),
    ]


class FILTER_MESSAGE_HEADER(ctypes.Structure):
    _fields_ = [
        ("ReplyLength", wt.DWORD),
        ("MessageId", ctypes.c_ulonglong),
    ]


class CYBERARMOR_FILTER_MESSAGE(ctypes.Structure):
    _fields_ = [
        ("Header", FILTER_MESSAGE_HEADER),
        ("Event", CYBERARMOR_EVENT),
    ]


class CYBERARMOR_COMMAND_PAYLOAD(ctypes.Union):
    _fields_ = [
        ("Mode", wt.DWORD),
        ("IPAddress", wt.DWORD),
        ("Path", wt.WCHAR * 520),
    ]


class CYBERARMOR_COMMAND_MESSAGE(ctypes.Structure):
    _fields_ = [
        ("Command", wt.DWORD),
        ("Payload", CYBERARMOR_COMMAND_PAYLOAD),
    ]


# Kernel command enum (must match driver)
COMMAND_SET_MODE = 1
ACTION_MONITOR = 0
ACTION_BLOCK = 1


EVENT_TYPE_NAMES = {
    1: "file_create",
    2: "file_write",
    3: "file_delete",
    4: "process_create",
    5: "process_terminate",
    6: "network_connect",
}

SEVERITY_NAMES = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

ACTION_NAMES = {
    0: "monitor",
    1: "block",
}


# ---------------------------------------------------------------------------
# Bridge configuration
# ---------------------------------------------------------------------------


@dataclass
class BridgeConfig:
    port_name: str = r"\\CyberArmorPort"
    reconnect_seconds: float = 3.0

    sinks: Set[str] = None  # type: ignore[assignment]

    eventlog_source: str = "CyberArmorKernelBridge"

    control_plane_url: str = "http://127.0.0.1:8000"
    control_plane_path: str = "/telemetry/ingest"
    api_key: str = ""
    tenant_id: str = ""
    user_id: str = "kernel-bridge"
    source_name: str = "endpoint"
    request_timeout_seconds: float = 5.0

    set_mode: Optional[str] = None

    @staticmethod
    def from_env(config_overrides: Optional[Dict[str, Any]] = None) -> "BridgeConfig":
        overrides = config_overrides or {}
        sinks_raw = os.getenv(
            "CYBERARMOR_BRIDGE_SINKS",
            str(overrides.get("sinks", "eventlog,control-plane")),
        )
        sinks = {s.strip().lower() for s in sinks_raw.split(",") if s.strip()}
        if not sinks:
            sinks = {"eventlog", "control-plane"}

        user_id = os.getenv("CYBERARMOR_BRIDGE_USER_ID", str(overrides.get("user_id", "")))
        if not user_id:
            user_id = f"{socket.gethostname()}\\{os.getenv('USERNAME', 'SYSTEM')}"

        cfg = BridgeConfig(
            port_name=os.getenv("CYBERARMOR_BRIDGE_PORT", str(overrides.get("port_name", r"\\CyberArmorPort"))),
            reconnect_seconds=float(os.getenv("CYBERARMOR_BRIDGE_RECONNECT_SECONDS", str(overrides.get("reconnect_seconds", "3")))),
            sinks=sinks,
            eventlog_source=os.getenv("CYBERARMOR_EVENTLOG_SOURCE", str(overrides.get("eventlog_source", "CyberArmorKernelBridge"))),
            control_plane_url=os.getenv("CYBERARMOR_CONTROL_PLANE_URL", str(overrides.get("control_plane_url", "http://127.0.0.1:8000"))),
            control_plane_path=os.getenv("CYBERARMOR_CONTROL_PLANE_PATH", str(overrides.get("control_plane_path", "/telemetry/ingest"))),
            api_key=os.getenv("CYBERARMOR_API_KEY", str(overrides.get("api_key", ""))),
            tenant_id=os.getenv("CYBERARMOR_TENANT_ID", str(overrides.get("tenant_id", ""))),
            user_id=user_id,
            source_name=os.getenv("CYBERARMOR_BRIDGE_SOURCE", str(overrides.get("source_name", "endpoint"))),
            request_timeout_seconds=float(os.getenv("CYBERARMOR_BRIDGE_TIMEOUT_SECONDS", str(overrides.get("request_timeout_seconds", "5")))),
            set_mode=os.getenv("CYBERARMOR_BRIDGE_SET_MODE", overrides.get("set_mode", None)),
        )

        if "control-plane" in cfg.sinks and (not cfg.api_key or not cfg.tenant_id):
            logging.getLogger("cyberarmor.kernel.bridge").warning(
                "control-plane sink configured but CYBERARMOR_API_KEY or CYBERARMOR_TENANT_ID is missing; "
                "control-plane forwarding will fail until configured"
            )

        return cfg


def _load_config_file(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("bridge config must be a JSON object")
    return data


# ---------------------------------------------------------------------------
# Bridge implementation
# ---------------------------------------------------------------------------


class KernelBridge:
    def __init__(self, config: BridgeConfig) -> None:
        self.cfg = config
        self.log = logging.getLogger("cyberarmor.kernel.bridge")

        self._fltlib = ctypes.WinDLL("FltLib.dll")
        self._kernel32 = ctypes.WinDLL("kernel32.dll")
        self._advapi32 = ctypes.WinDLL("advapi32.dll")

        self._configure_native_prototypes()

    def _configure_native_prototypes(self) -> None:
        self._fltlib.FilterConnectCommunicationPort.argtypes = [
            wt.LPCWSTR, wt.DWORD, wt.LPVOID, wt.WORD, wt.LPVOID, ctypes.POINTER(wt.HANDLE)
        ]
        self._fltlib.FilterConnectCommunicationPort.restype = wt.HRESULT

        self._fltlib.FilterGetMessage.argtypes = [
            wt.HANDLE, wt.LPVOID, wt.DWORD, wt.LPVOID
        ]
        self._fltlib.FilterGetMessage.restype = wt.HRESULT

        self._fltlib.FilterSendMessage.argtypes = [
            wt.HANDLE, wt.LPVOID, wt.DWORD, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD)
        ]
        self._fltlib.FilterSendMessage.restype = wt.HRESULT

        self._kernel32.CloseHandle.argtypes = [wt.HANDLE]
        self._kernel32.CloseHandle.restype = wt.BOOL

        self._advapi32.RegisterEventSourceW.argtypes = [wt.LPCWSTR, wt.LPCWSTR]
        self._advapi32.RegisterEventSourceW.restype = wt.HANDLE

        self._advapi32.ReportEventW.argtypes = [
            wt.HANDLE, wt.WORD, wt.WORD, wt.DWORD, wt.LPVOID, wt.WORD,
            wt.DWORD, ctypes.POINTER(wt.LPCWSTR), wt.LPVOID,
        ]
        self._advapi32.ReportEventW.restype = wt.BOOL

        self._advapi32.DeregisterEventSource.argtypes = [wt.HANDLE]
        self._advapi32.DeregisterEventSource.restype = wt.BOOL

    @staticmethod
    def _wstring_value(chars: Iterable[str]) -> str:
        raw = "".join(chars)
        return raw.split("\x00", 1)[0]

    @staticmethod
    def _windows_filetime_to_iso_utc(filetime_100ns: int) -> str:
        # Windows FILETIME epoch: 1601-01-01 UTC in 100ns ticks.
        base = datetime(1601, 1, 1, tzinfo=timezone.utc)
        dt = base + timedelta(microseconds=filetime_100ns / 10.0)
        return dt.isoformat()

    @staticmethod
    def _ipv4_from_u32_network_order(addr: int) -> str:
        b0 = (addr >> 24) & 0xFF
        b1 = (addr >> 16) & 0xFF
        b2 = (addr >> 8) & 0xFF
        b3 = addr & 0xFF
        return f"{b0}.{b1}.{b2}.{b3}"

    def _event_to_dict(self, ev: CYBERARMOR_EVENT) -> Dict[str, Any]:
        event_type = EVENT_TYPE_NAMES.get(ev.EventType, f"unknown_{ev.EventType}")
        payload: Dict[str, Any] = {
            "event_type_code": ev.EventType,
            "severity": SEVERITY_NAMES.get(ev.Severity, str(ev.Severity)),
            "severity_code": ev.Severity,
            "action": ACTION_NAMES.get(ev.Action, str(ev.Action)),
            "action_code": ev.Action,
            "process_id": ev.ProcessId,
            "thread_id": ev.ThreadId,
            "process_name": self._wstring_value(ev.ProcessName),
            "kernel_timestamp": self._windows_filetime_to_iso_utc(ev.Timestamp),
        }

        if ev.EventType == 1:
            payload.update({
                "file_path": self._wstring_value(ev.Data.FileCreate.FilePath),
                "desired_access": int(ev.Data.FileCreate.DesiredAccess),
                "create_disposition": int(ev.Data.FileCreate.CreateDisposition),
                "is_directory": bool(ev.Data.FileCreate.IsDirectory),
            })
        elif ev.EventType == 2:
            payload.update({
                "file_path": self._wstring_value(ev.Data.FileWrite.FilePath),
                "write_length": int(ev.Data.FileWrite.WriteLength),
            })
        elif ev.EventType == 3:
            payload.update({"file_path": self._wstring_value(ev.Data.FileDelete.FilePath)})
        elif ev.EventType == 4:
            payload.update({
                "child_process_id": int(ev.Data.ProcessCreate.ChildProcessId),
                "image_file_name": self._wstring_value(ev.Data.ProcessCreate.ImageFileName),
                "command_line": self._wstring_value(ev.Data.ProcessCreate.CommandLine),
            })
        elif ev.EventType == 5:
            payload.update({"exit_code": int(ev.Data.ProcessTerminate.ExitCode)})
        elif ev.EventType == 6:
            payload.update({
                "remote_ip": self._ipv4_from_u32_network_order(ev.Data.NetworkConnect.RemoteAddress),
                "remote_port": int(ev.Data.NetworkConnect.RemotePort),
                "local_port": int(ev.Data.NetworkConnect.LocalPort),
                "protocol": int(ev.Data.NetworkConnect.Protocol),
            })

        return {
            "tenant_id": self.cfg.tenant_id,
            "user_id": self.cfg.user_id,
            "event_type": event_type,
            "payload": payload,
            "source": self.cfg.source_name,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
        }

    def _eventlog_type(self, severity_code: int) -> int:
        if severity_code >= 4:
            return EVENTLOG_ERROR_TYPE
        if severity_code >= 2:
            return EVENTLOG_WARNING_TYPE
        return EVENTLOG_INFORMATION_TYPE

    def _send_to_eventlog(self, event: Dict[str, Any]) -> None:
        h_src = self._advapi32.RegisterEventSourceW(None, self.cfg.eventlog_source)
        if not h_src or h_src == INVALID_HANDLE_VALUE:
            raise OSError("RegisterEventSourceW failed")

        try:
            msg = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
            strings = (wt.LPCWSTR * 1)(msg)
            severity = int(event.get("payload", {}).get("severity_code", 0))

            ok = self._advapi32.ReportEventW(
                h_src,
                self._eventlog_type(severity),
                0,
                1000 + int(event.get("payload", {}).get("event_type_code", 0)),
                None,
                1,
                0,
                strings,
                None,
            )
            if not ok:
                raise OSError("ReportEventW failed")
        finally:
            self._advapi32.DeregisterEventSource(h_src)

    def _send_to_control_plane(self, event: Dict[str, Any]) -> None:
        url = self.cfg.control_plane_url.rstrip("/") + self.cfg.control_plane_path
        body = json.dumps(event).encode("utf-8")
        req = urllib.request.Request(url=url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("x-api-key", self.cfg.api_key)
        if self.cfg.tenant_id:
            req.add_header("x-tenant-id", self.cfg.tenant_id)

        with urllib.request.urlopen(req, timeout=self.cfg.request_timeout_seconds) as resp:
            if resp.status not in (200, 201, 202, 204):
                raise RuntimeError(f"control-plane non-OK status={resp.status}")

    def _set_kernel_mode(self, port_handle: wt.HANDLE, mode_name: str) -> None:
        mode_name = mode_name.strip().lower()
        if mode_name not in {"monitor", "block", "enforce"}:
            raise ValueError("CYBERARMOR_BRIDGE_SET_MODE must be monitor|block|enforce")

        mode = ACTION_BLOCK if mode_name in {"block", "enforce"} else ACTION_MONITOR

        cmd = CYBERARMOR_COMMAND_MESSAGE()
        cmd.Command = COMMAND_SET_MODE
        cmd.Payload.Mode = mode

        bytes_returned = wt.DWORD(0)
        hr = self._fltlib.FilterSendMessage(
            port_handle,
            ctypes.byref(cmd),
            ctypes.sizeof(cmd),
            None,
            0,
            ctypes.byref(bytes_returned),
        )
        if hr != S_OK:
            raise RuntimeError(f"FilterSendMessage(set mode={mode_name}) failed HRESULT=0x{hr & 0xFFFFFFFF:08X}")

        self.log.info("kernel mode set to %s", mode_name)

    def _connect_port(self) -> wt.HANDLE:
        port = wt.HANDLE()
        hr = self._fltlib.FilterConnectCommunicationPort(
            self.cfg.port_name,
            0,
            None,
            0,
            None,
            ctypes.byref(port),
        )
        if hr != S_OK:
            raise RuntimeError(
                f"FilterConnectCommunicationPort({self.cfg.port_name}) failed HRESULT=0x{hr & 0xFFFFFFFF:08X}"
            )

        self.log.info("connected to minifilter port %s", self.cfg.port_name)

        if self.cfg.set_mode:
            self._set_kernel_mode(port, self.cfg.set_mode)

        return port

    def _dispatch(self, event: Dict[str, Any]) -> None:
        if "eventlog" in self.cfg.sinks:
            try:
                self._send_to_eventlog(event)
            except Exception as exc:
                self.log.error("eventlog sink failed: %s", exc)

        if "control-plane" in self.cfg.sinks:
            try:
                self._send_to_control_plane(event)
            except urllib.error.HTTPError as exc:
                self.log.error("control-plane sink HTTP %s: %s", exc.code, exc.reason)
            except Exception as exc:
                self.log.error("control-plane sink failed: %s", exc)

    def run_forever(self) -> None:
        self.log.info("starting CyberArmor kernel bridge sinks=%s", sorted(self.cfg.sinks))

        while True:
            port_handle: Optional[wt.HANDLE] = None
            try:
                port_handle = self._connect_port()

                while True:
                    msg = CYBERARMOR_FILTER_MESSAGE()
                    hr = self._fltlib.FilterGetMessage(
                        port_handle,
                        ctypes.byref(msg),
                        ctypes.sizeof(msg),
                        None,
                    )
                    if hr != S_OK:
                        raise RuntimeError(f"FilterGetMessage failed HRESULT=0x{hr & 0xFFFFFFFF:08X}")

                    event = self._event_to_dict(msg.Event)
                    self._dispatch(event)
                    self.log.debug("event forwarded type=%s", event["event_type"])

            except KeyboardInterrupt:
                self.log.info("bridge stopping by keyboard interrupt")
                break
            except Exception as exc:
                self.log.warning("bridge loop error: %s", exc)
                time.sleep(self.cfg.reconnect_seconds)
            finally:
                if port_handle:
                    self._kernel32.CloseHandle(port_handle)


def main() -> int:
    if os.name != "nt":
        print("This bridge only runs on Windows.", file=sys.stderr)
        return 2

    parser = argparse.ArgumentParser(description="CyberArmor Windows kernel bridge")
    parser.add_argument(
        "--config",
        default=None,
        help="Optional JSON config file (env vars still take precedence).",
    )
    args = parser.parse_args()

    log_level = os.getenv("CYBERARMOR_BRIDGE_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    config_overrides = _load_config_file(args.config)
    cfg = BridgeConfig.from_env(config_overrides=config_overrides)
    bridge = KernelBridge(cfg)
    bridge.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
