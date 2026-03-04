"""Cross-Platform Installer for AIShields Endpoint Agent.

Handles:
- Dependency verification and installation
- Platform-specific service registration (launchd, systemd, Windows Service)
- Configuration file deployment
- Auto-update mechanism
- Uninstallation / cleanup
- Silent / headless installation mode
"""

import argparse
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("endpoint.installer")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PRODUCT_NAME = "AIShields Endpoint Agent"
SERVICE_NAME = "aishields-endpoint"
BUNDLE_ID = "com.aishields.endpoint"
VERSION = "1.0.0"

# Default install paths per platform
INSTALL_PATHS = {
    "Darwin": Path("/usr/local/aishields"),
    "Linux": Path("/opt/aishields"),
    "Windows": Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "AIShields",
}

CONFIG_PATHS = {
    "Darwin": Path("/etc/aishields"),
    "Linux": Path("/etc/aishields"),
    "Windows": Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "AIShields",
}

LOG_PATHS = {
    "Darwin": Path("/var/log/aishields"),
    "Linux": Path("/var/log/aishields"),
    "Windows": Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "AIShields" / "logs",
}


# ---------------------------------------------------------------------------
# Platform Detection
# ---------------------------------------------------------------------------

def get_platform() -> str:
    return platform.system()


def is_root() -> bool:
    if get_platform() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "control_plane_url": "https://localhost:8000",
    "api_key": "",
    "tenant_id": "",
    "policy_sync_interval_seconds": 60,
    "telemetry_interval_seconds": 30,
    "log_level": "INFO",
    "monitors": {
        "process": True,
        "file": True,
        "network": True,
        "ai_tool": True,
    },
    "dlp": {
        "enabled": True,
        "scan_clipboard": True,
        "custom_labels_sync": True,
    },
    "zero_day": {
        "rce_guard": True,
        "sandbox_analysis": True,
        "quarantine_enabled": True,
    },
    "crypto": {
        "fips_mode": False,
        "pqc_enabled": True,
        "pqc_fallback": True,
    },
    "proxy": {
        "enabled": False,
        "proxy_url": "",
        "no_proxy": "localhost,127.0.0.1",
    },
}


def write_config(config_dir: Path, config: Dict) -> Path:
    """Write agent configuration file."""
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / "agent.json"
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(str(config_file), 0o600)
    logger.info("Configuration written to %s", config_file)
    return config_file


# ---------------------------------------------------------------------------
# Dependency Checks
# ---------------------------------------------------------------------------

PYTHON_MIN_VERSION = (3, 9)

REQUIRED_PACKAGES = [
    "psutil",
    "watchdog",
    "cryptography",
    "httpx",
    "pydantic",
]

OPTIONAL_PACKAGES = {
    "oqs": "Post-Quantum Cryptography (liboqs)",
    "scapy": "Deep packet inspection",
}


def check_python_version() -> bool:
    """Check Python version meets minimum requirements."""
    current = sys.version_info[:2]
    if current < PYTHON_MIN_VERSION:
        logger.error(
            "Python %s.%s required, found %s.%s",
            *PYTHON_MIN_VERSION, *current,
        )
        return False
    logger.info("Python version: %s.%s ✓", *current)
    return True


def check_dependencies() -> List[str]:
    """Check for missing Python packages."""
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(pkg)
            logger.info("  ✓ %s", pkg)
        except ImportError:
            missing.append(pkg)
            logger.warning("  ✗ %s (missing)", pkg)

    for pkg, desc in OPTIONAL_PACKAGES.items():
        try:
            __import__(pkg)
            logger.info("  ✓ %s (%s)", pkg, desc)
        except ImportError:
            logger.info("  ○ %s (%s) — optional, not installed", pkg, desc)

    return missing


def install_dependencies(missing: List[str]) -> bool:
    """Install missing Python dependencies."""
    if not missing:
        return True
    logger.info("Installing missing packages: %s", ", ".join(missing))
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "--quiet",
            *missing,
        ])
        logger.info("Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Failed to install dependencies: %s", e)
        return False


# ---------------------------------------------------------------------------
# macOS Service (launchd)
# ---------------------------------------------------------------------------

LAUNCHD_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{bundle_id}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>{agent_path}</string>
        <string>--config</string>
        <string>{config_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{log_dir}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/agent.err</string>
    <key>WorkingDirectory</key>
    <string>{install_dir}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>AISHIELDS_CONFIG</key>
        <string>{config_path}</string>
    </dict>
    <key>ProcessType</key>
    <string>Background</string>
    <key>ThrottleInterval</key>
    <integer>5</integer>
</dict>
</plist>
"""


def install_macos_service(install_dir: Path, config_path: Path, log_dir: Path) -> bool:
    """Install launchd service on macOS."""
    plist_path = Path("/Library/LaunchDaemons") / f"{BUNDLE_ID}.plist"
    agent_path = install_dir / "agent.py"

    content = LAUNCHD_PLIST.format(
        bundle_id=BUNDLE_ID,
        python=sys.executable,
        agent_path=agent_path,
        config_path=config_path,
        log_dir=log_dir,
        install_dir=install_dir,
    )

    try:
        plist_path.write_text(content)
        os.chmod(str(plist_path), 0o644)
        subprocess.run(["launchctl", "load", str(plist_path)], check=True)
        logger.info("macOS launchd service installed: %s", plist_path)
        return True
    except Exception as e:
        logger.error("Failed to install launchd service: %s", e)
        return False


def uninstall_macos_service() -> bool:
    """Remove launchd service on macOS."""
    plist_path = Path("/Library/LaunchDaemons") / f"{BUNDLE_ID}.plist"
    try:
        subprocess.run(["launchctl", "unload", str(plist_path)], check=False)
        plist_path.unlink(missing_ok=True)
        logger.info("macOS launchd service removed")
        return True
    except Exception as e:
        logger.error("Failed to uninstall launchd service: %s", e)
        return False


# ---------------------------------------------------------------------------
# Linux Service (systemd)
# ---------------------------------------------------------------------------

SYSTEMD_UNIT = """[Unit]
Description=AIShields Endpoint Agent
Documentation=https://docs.aishields.ai/endpoint
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={python} {agent_path} --config {config_path}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier={service_name}
WorkingDirectory={install_dir}
Environment=AISHIELDS_CONFIG={config_path}

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths={log_dir} {config_dir}

[Install]
WantedBy=multi-user.target
"""


def install_linux_service(install_dir: Path, config_path: Path, config_dir: Path, log_dir: Path) -> bool:
    """Install systemd service on Linux."""
    unit_path = Path("/etc/systemd/system") / f"{SERVICE_NAME}.service"
    agent_path = install_dir / "agent.py"

    content = SYSTEMD_UNIT.format(
        python=sys.executable,
        agent_path=agent_path,
        config_path=config_path,
        config_dir=config_dir,
        service_name=SERVICE_NAME,
        install_dir=install_dir,
        log_dir=log_dir,
    )

    try:
        unit_path.write_text(content)
        os.chmod(str(unit_path), 0o644)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", SERVICE_NAME], check=True)
        subprocess.run(["systemctl", "start", SERVICE_NAME], check=True)
        logger.info("Linux systemd service installed and started: %s", unit_path)
        return True
    except Exception as e:
        logger.error("Failed to install systemd service: %s", e)
        return False


def uninstall_linux_service() -> bool:
    """Remove systemd service on Linux."""
    unit_path = Path("/etc/systemd/system") / f"{SERVICE_NAME}.service"
    try:
        subprocess.run(["systemctl", "stop", SERVICE_NAME], check=False)
        subprocess.run(["systemctl", "disable", SERVICE_NAME], check=False)
        unit_path.unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        logger.info("Linux systemd service removed")
        return True
    except Exception as e:
        logger.error("Failed to uninstall systemd service: %s", e)
        return False


# ---------------------------------------------------------------------------
# Windows Service (NSSM or native)
# ---------------------------------------------------------------------------

WINDOWS_SERVICE_PS = """
$serviceName = "{service_name}"
$displayName = "{display_name}"
$python = "{python}"
$agentPath = "{agent_path}"
$configPath = "{config_path}"

# Check if NSSM is available for easier service management
$nssm = Get-Command nssm -ErrorAction SilentlyContinue
if ($nssm) {{
    & nssm install $serviceName $python $agentPath --config $configPath
    & nssm set $serviceName DisplayName $displayName
    & nssm set $serviceName Description "AIShields AI Security Endpoint Agent"
    & nssm set $serviceName Start SERVICE_AUTO_START
    & nssm set $serviceName AppStdout "{log_dir}\\agent.log"
    & nssm set $serviceName AppStderr "{log_dir}\\agent.err"
    & nssm start $serviceName
}} else {{
    # Use sc.exe as fallback
    $binPath = "`"$python`" `"$agentPath`" --config `"$configPath`""
    & sc.exe create $serviceName binPath= $binPath DisplayName= $displayName start= auto
    & sc.exe description $serviceName "AIShields AI Security Endpoint Agent"
    & sc.exe start $serviceName
}}
"""


def install_windows_service(install_dir: Path, config_path: Path, log_dir: Path) -> bool:
    """Install Windows service."""
    agent_path = install_dir / "agent.py"
    ps_script = WINDOWS_SERVICE_PS.format(
        service_name=SERVICE_NAME,
        display_name=PRODUCT_NAME,
        python=sys.executable,
        agent_path=agent_path,
        config_path=config_path,
        log_dir=log_dir,
    )

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ps1", delete=False) as f:
            f.write(ps_script)
            ps_path = f.name
        subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", ps_path],
            check=True,
        )
        os.unlink(ps_path)
        logger.info("Windows service installed: %s", SERVICE_NAME)
        return True
    except Exception as e:
        logger.error("Failed to install Windows service: %s", e)
        return False


def uninstall_windows_service() -> bool:
    """Remove Windows service."""
    try:
        subprocess.run(["sc", "stop", SERVICE_NAME], check=False)
        subprocess.run(["sc", "delete", SERVICE_NAME], check=True)
        logger.info("Windows service removed")
        return True
    except Exception as e:
        logger.error("Failed to uninstall Windows service: %s", e)
        return False


# ---------------------------------------------------------------------------
# File Deployment
# ---------------------------------------------------------------------------

def deploy_files(source_dir: Path, install_dir: Path) -> bool:
    """Copy agent files to installation directory."""
    try:
        if install_dir.exists():
            logger.info("Updating existing installation at %s", install_dir)
            # Preserve config, remove old code
            for item in install_dir.iterdir():
                if item.name not in ("agent.json", "data", "quarantine"):
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
        else:
            install_dir.mkdir(parents=True, exist_ok=True)

        # Copy all Python files and subdirectories
        for item in source_dir.iterdir():
            dest = install_dir / item.name
            if item.is_dir():
                shutil.copytree(item, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dest)

        logger.info("Files deployed to %s", install_dir)
        return True
    except Exception as e:
        logger.error("Failed to deploy files: %s", e)
        return False


# ---------------------------------------------------------------------------
# Main Installer Logic
# ---------------------------------------------------------------------------

def install(
    control_plane_url: str = "",
    api_key: str = "",
    tenant_id: str = "",
    silent: bool = False,
    skip_service: bool = False,
    install_dir: Optional[Path] = None,
) -> bool:
    """Full installation process."""
    plat = get_platform()
    logger.info("=" * 60)
    logger.info("  %s Installer v%s", PRODUCT_NAME, VERSION)
    logger.info("  Platform: %s (%s)", plat, platform.machine())
    logger.info("=" * 60)

    # 1. Check privileges
    if not is_root() and plat != "Windows":
        logger.warning("Not running as root — service installation may fail")

    # 2. Check Python version
    if not check_python_version():
        return False

    # 3. Check/install dependencies
    logger.info("\nChecking dependencies...")
    missing = check_dependencies()
    if missing:
        if not silent:
            resp = input(f"\nInstall missing packages ({', '.join(missing)})? [Y/n] ")
            if resp.lower() == "n":
                logger.error("Cannot proceed without required dependencies")
                return False
        if not install_dependencies(missing):
            return False

    # 4. Determine paths
    if install_dir is None:
        install_dir = INSTALL_PATHS.get(plat, Path("/opt/aishields"))
    config_dir = CONFIG_PATHS.get(plat, Path("/etc/aishields"))
    log_dir = LOG_PATHS.get(plat, Path("/var/log/aishields"))

    # 5. Create directories
    for d in [install_dir, config_dir, log_dir]:
        d.mkdir(parents=True, exist_ok=True)
        logger.info("Directory: %s", d)

    # 6. Deploy files
    source_dir = Path(__file__).parent
    if not deploy_files(source_dir, install_dir):
        return False

    # 7. Write configuration
    config = DEFAULT_CONFIG.copy()
    if control_plane_url:
        config["control_plane_url"] = control_plane_url
    if api_key:
        config["api_key"] = api_key
    if tenant_id:
        config["tenant_id"] = tenant_id

    config_path = write_config(config_dir, config)

    # 8. Install platform service
    if not skip_service:
        logger.info("\nInstalling system service...")
        if plat == "Darwin":
            install_macos_service(install_dir, config_path, log_dir)
        elif plat == "Linux":
            install_linux_service(install_dir, config_path, config_dir, log_dir)
        elif plat == "Windows":
            install_windows_service(install_dir, config_path, log_dir)
    else:
        logger.info("Skipping service installation (--skip-service)")

    logger.info("\n" + "=" * 60)
    logger.info("  Installation complete!")
    logger.info("  Install dir:  %s", install_dir)
    logger.info("  Config:       %s", config_path)
    logger.info("  Logs:         %s", log_dir)
    logger.info("=" * 60)
    return True


def uninstall(purge: bool = False) -> bool:
    """Uninstall the endpoint agent."""
    plat = get_platform()
    logger.info("Uninstalling %s...", PRODUCT_NAME)

    # Stop and remove service
    if plat == "Darwin":
        uninstall_macos_service()
    elif plat == "Linux":
        uninstall_linux_service()
    elif plat == "Windows":
        uninstall_windows_service()

    install_dir = INSTALL_PATHS.get(plat)
    if install_dir and install_dir.exists():
        shutil.rmtree(install_dir)
        logger.info("Removed %s", install_dir)

    if purge:
        config_dir = CONFIG_PATHS.get(plat)
        log_dir = LOG_PATHS.get(plat)
        if config_dir and config_dir.exists():
            shutil.rmtree(config_dir)
            logger.info("Removed config: %s", config_dir)
        if log_dir and log_dir.exists():
            shutil.rmtree(log_dir)
            logger.info("Removed logs: %s", log_dir)

    logger.info("Uninstallation complete")
    return True


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=f"{PRODUCT_NAME} Installer")
    sub = parser.add_subparsers(dest="command", help="Command")

    # Install command
    inst = sub.add_parser("install", help="Install the endpoint agent")
    inst.add_argument("--control-plane-url", default="", help="Control plane URL")
    inst.add_argument("--api-key", default="", help="API key for authentication")
    inst.add_argument("--tenant-id", default="", help="Tenant identifier")
    inst.add_argument("--silent", action="store_true", help="Silent installation")
    inst.add_argument("--skip-service", action="store_true", help="Skip service registration")
    inst.add_argument("--install-dir", type=Path, default=None, help="Custom install directory")

    # Uninstall command
    uninst = sub.add_parser("uninstall", help="Uninstall the endpoint agent")
    uninst.add_argument("--purge", action="store_true", help="Remove config and logs too")

    # Status command
    sub.add_parser("status", help="Check installation status")

    args = parser.parse_args()

    if args.command == "install":
        success = install(
            control_plane_url=args.control_plane_url,
            api_key=args.api_key,
            tenant_id=args.tenant_id,
            silent=args.silent,
            skip_service=args.skip_service,
            install_dir=args.install_dir,
        )
        sys.exit(0 if success else 1)
    elif args.command == "uninstall":
        success = uninstall(purge=args.purge)
        sys.exit(0 if success else 1)
    elif args.command == "status":
        plat = get_platform()
        install_dir = INSTALL_PATHS.get(plat)
        config_dir = CONFIG_PATHS.get(plat)
        print(f"Platform:    {plat}")
        print(f"Install dir: {install_dir} {'✓' if install_dir and install_dir.exists() else '✗'}")
        print(f"Config dir:  {config_dir} {'✓' if config_dir and config_dir.exists() else '✗'}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
