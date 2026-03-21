# CyberArmor Windows Kernel Sensor

This directory contains the Windows minifilter driver and a usermode bridge.

## Files

- `cyberarmor_minifilter.c/.h/.inf`: kernel minifilter driver
- `cyberarmor_usermode_bridge.py`: usermode bridge for receiving minifilter events

## Usermode Bridge

The bridge connects to `\\CyberArmorPort` using `FltLib`, receives kernel events,
and forwards them to one or both sinks:

- Windows Event Log (Application)
- Control plane telemetry ingest (`/telemetry/ingest`)

### Environment variables

- `CYBERARMOR_BRIDGE_SINKS`: `eventlog`, `control-plane`, or both (comma-separated)
- `CYBERARMOR_BRIDGE_PORT`: default `\\CyberArmorPort`
- `CYBERARMOR_EVENTLOG_SOURCE`: default `CyberArmorKernelBridge`
- `CYBERARMOR_CONTROL_PLANE_URL`: e.g. `https://control-plane.example.com`
- `CYBERARMOR_CONTROL_PLANE_PATH`: default `/telemetry/ingest`
- `CYBERARMOR_API_KEY`: required for control-plane sink
- `CYBERARMOR_TENANT_ID`: required for control-plane sink
- `CYBERARMOR_BRIDGE_USER_ID`: optional telemetry user_id
- `CYBERARMOR_BRIDGE_SOURCE`: telemetry source field (default `endpoint`)
- `CYBERARMOR_BRIDGE_SET_MODE`: optional `monitor` or `block`
- `CYBERARMOR_BRIDGE_LOG_LEVEL`: `DEBUG|INFO|WARNING|ERROR`

### Run

```powershell
$env:CYBERARMOR_BRIDGE_SINKS = "eventlog,control-plane"
$env:CYBERARMOR_CONTROL_PLANE_URL = "https://control-plane.example.com"
$env:CYBERARMOR_API_KEY = "<api-key>"
$env:CYBERARMOR_TENANT_ID = "tenant-123"
python .\kernel\windows\cyberarmor_usermode_bridge.py
```

Or with a JSON config file:

```powershell
python .\kernel\windows\cyberarmor_usermode_bridge.py --config "C:\ProgramData\CyberArmor\kernel_bridge.json"
```

### Notes

- The bridge must run elevated and after the minifilter is loaded.
- `agents/endpoint-agent/installer.py install` registers a Windows service:
  `cyberarmor-kernel-bridge`.
