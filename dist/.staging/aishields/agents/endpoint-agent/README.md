# AIShields Endpoint Agent

Cross-platform endpoint security agent for monitoring and protecting AI tool usage on macOS, Windows, and Linux.

## Features

- **Process Monitoring**: Detect AI application launches (ChatGPT, Copilot, Claude, etc.)
- **Network Monitoring**: Intercept connections to 30+ AI API endpoints
- **File Monitoring**: Watch for sensitive data in AI-related file operations
- **DLP Scanner**: Real-time data classification and sensitive data detection
- **Zero-Day RCE Guard**: Sandbox untrusted AI-generated code execution
- **PQC Crypto**: ML-KEM-1024 key transport, ML-DSA-87 telemetry signing
- **Platform Integration**: Native OS security hooks (SIP, Defender, SELinux/AppArmor)
- **Policy Enforcement**: Real-time policy evaluation against control plane

## Supported Platforms

| Platform | Security Hooks |
|----------|---------------|
| macOS | SIP, FileVault, Gatekeeper, TCC, codesign, quarantine, launchd |
| Windows | Defender, BitLocker, AMSI, Authenticode, MOTW, ETW, AppLocker |
| Linux | SELinux, AppArmor, seccomp, eBPF, auditd, bubblewrap sandbox |

## Installation

```bash
pip install -r requirements.txt

# Install as system service (requires admin/root)
sudo python installer.py install \
  --server https://your-aishields-server \
  --api-key YOUR_API_KEY \
  --tenant-id YOUR_TENANT_ID

# Check status
python installer.py status

# Uninstall
sudo python installer.py uninstall
```

## Docker

```bash
docker build -t aishields-endpoint-agent .
docker run -d \
  -e CONTROL_PLANE_URL=https://your-server:8000 \
  -e API_KEY=YOUR_KEY \
  -e TENANT_ID=YOUR_TENANT \
  --name aishields-agent \
  aishields-endpoint-agent
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `CONTROL_PLANE_URL` | Control plane endpoint | `http://localhost:8000` |
| `API_KEY` | PQC-encrypted API key | (required) |
| `TENANT_ID` | Tenant identifier | (required) |
| `SCAN_INTERVAL` | Monitor polling interval (seconds) | `5` |
| `DLP_ENABLED` | Enable DLP scanning | `true` |
| `PQC_ENABLED` | Enable post-quantum crypto | `true` |
| `LOG_LEVEL` | Logging level | `INFO` |

## Architecture

```
endpoint-agent/
├── agent.py              # Main agent orchestrator
├── installer.py          # Cross-platform service installer
├── policy_enforcer.py    # Policy evaluation client
├── crypto/
│   ├── fips.py           # FIPS 140-3 crypto module
│   └── pqc.py            # PQC key transport & signing
├── dlp/
│   ├── scanner.py        # Pattern-based DLP scanner
│   ├── classifier.py     # Content classification engine
│   └── custom_labels.py  # Custom data label definitions
├── monitors/
│   ├── process_monitor.py    # AI process detection
│   ├── network_monitor.py    # Network connection monitoring
│   ├── file_monitor.py       # File system watcher
│   └── ai_tool_detector.py   # AI tool fingerprinting
├── platform/
│   ├── macos.py          # macOS security integration
│   ├── windows.py        # Windows security integration
│   └── linux.py          # Linux security integration
└── zero_day/
    ├── rce_guard.py      # Remote code execution prevention
    └── sandbox.py        # Code execution sandbox
```
