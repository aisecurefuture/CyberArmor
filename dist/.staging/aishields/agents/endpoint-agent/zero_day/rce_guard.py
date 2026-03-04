"""Zero-Day Remote Code Execution Guard.

Blocks execution of unsigned/unknown binaries downloaded from the internet.
Zero-trust approach: deny-by-default for unknown executables.
"""

import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger("rce_guard")

QUARANTINE_DIR = Path(os.getenv("AISHIELDS_QUARANTINE_DIR", os.path.expanduser("~/.aishields/quarantine")))


@dataclass
class BinaryAnalysis:
    path: str
    sha256: str = ""
    signed: bool = False
    signer: str = ""
    trusted: bool = False
    risk_level: str = "unknown"  # safe, low, medium, high, critical
    reasons: List[str] = field(default_factory=list)
    quarantined: bool = False


# Patterns indicating suspicious executable behavior
SUSPICIOUS_PATTERNS = {
    "encoded_powershell": [
        "-encodedcommand", "-enc ", "-e ", "powershell -nop", "powershell -w hidden",
        "iex(", "invoke-expression", "downloadstring", "webclient",
    ],
    "script_from_temp": ["/tmp/", "\\temp\\", "\\appdata\\local\\temp\\"],
    "suspicious_child_chain": ["cmd.exe /c", "bash -c", "sh -c", "python -c", "perl -e"],
    "fileless_indicators": [
        "reflection.assembly", "loadlibrary", "virtualalloc", "createremotethread",
    ],
}

# Known trusted publisher certificate subjects
DEFAULT_TRUSTED_PUBLISHERS = {
    "Microsoft Corporation", "Apple Inc.", "Google LLC", "Mozilla Corporation",
    "Canonical Ltd.", "Red Hat, Inc.", "JetBrains s.r.o.",
}


class RCEGuard:
    """Zero-day remote code execution protection.

    Features:
    - Block unsigned/unknown binary execution from internet downloads
    - Code signature verification
    - Trusted publisher allow list
    - Quarantine suspicious executables
    - Fileless malware detection
    - Zero-trust: deny-by-default for unknown executables
    """

    def __init__(self, trusted_publishers: Optional[Set[str]] = None, strict_mode: bool = True):
        self.trusted_publishers = trusted_publishers or DEFAULT_TRUSTED_PUBLISHERS.copy()
        self.strict_mode = strict_mode
        self._known_hashes: Dict[str, str] = {}  # sha256 -> "safe"/"malicious"
        self._blocked_paths: Set[str] = set()
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    def analyze_binary(self, file_path: str) -> BinaryAnalysis:
        """Analyze a binary before execution. Returns risk assessment."""
        analysis = BinaryAnalysis(path=file_path)

        if not os.path.exists(file_path):
            analysis.risk_level = "unknown"
            analysis.reasons.append("File not found")
            return analysis

        # Compute hash
        analysis.sha256 = self._compute_sha256(file_path)

        # Check known hashes
        if analysis.sha256 in self._known_hashes:
            verdict = self._known_hashes[analysis.sha256]
            analysis.risk_level = "safe" if verdict == "safe" else "critical"
            analysis.trusted = verdict == "safe"
            return analysis

        # Check code signature
        analysis.signed, analysis.signer = self._check_signature(file_path)
        if analysis.signed and analysis.signer in self.trusted_publishers:
            analysis.trusted = True
            analysis.risk_level = "safe"
            self._known_hashes[analysis.sha256] = "safe"
            return analysis

        # Check if from internet download
        if self._is_internet_download(file_path):
            analysis.reasons.append("Downloaded from internet")
            analysis.risk_level = "high"

        # Check if in temp directory
        if self._is_temp_path(file_path):
            analysis.reasons.append("Executed from temp directory")
            analysis.risk_level = "high"

        # Check for suspicious patterns in file content (scripts)
        suspicious = self._check_suspicious_content(file_path)
        if suspicious:
            analysis.reasons.extend(suspicious)
            analysis.risk_level = "critical"

        # Unsigned binary from unknown source
        if not analysis.signed:
            analysis.reasons.append("Unsigned binary")
            if analysis.risk_level not in ("critical",):
                analysis.risk_level = "medium" if not self.strict_mode else "high"

        return analysis

    def should_block(self, analysis: BinaryAnalysis) -> bool:
        """Determine if execution should be blocked based on analysis."""
        if analysis.trusted:
            return False
        if self.strict_mode:
            return analysis.risk_level in ("high", "critical", "unknown")
        return analysis.risk_level in ("critical",)

    def quarantine(self, file_path: str) -> str:
        """Move suspicious binary to quarantine directory."""
        try:
            sha256 = self._compute_sha256(file_path)
            quarantine_name = f"{sha256}_{os.path.basename(file_path)}"
            quarantine_path = QUARANTINE_DIR / quarantine_name

            # Store metadata
            meta = {
                "original_path": file_path,
                "sha256": sha256,
                "quarantined_at": datetime.now(timezone.utc).isoformat(),
                "file_size": os.path.getsize(file_path),
            }
            (QUARANTINE_DIR / f"{quarantine_name}.json").write_text(json.dumps(meta))

            shutil.move(file_path, str(quarantine_path))
            os.chmod(str(quarantine_path), 0o000)
            self._blocked_paths.add(file_path)

            logger.warning("Quarantined: %s -> %s", file_path, quarantine_path)
            return str(quarantine_path)
        except Exception as e:
            logger.error("Quarantine failed for %s: %s", file_path, e)
            return ""

    def check_command_line(self, command: str) -> List[str]:
        """Check a command line for suspicious patterns (fileless malware indicators)."""
        findings = []
        cmd_lower = command.lower()
        for category, patterns in SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in cmd_lower:
                    findings.append(f"{category}: {pattern}")
        return findings

    def add_trusted_publisher(self, publisher: str):
        self.trusted_publishers.add(publisher)

    def add_known_hash(self, sha256: str, verdict: str):
        self._known_hashes[sha256] = verdict

    def _compute_sha256(self, file_path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except Exception:
            pass
        return h.hexdigest()

    def _check_signature(self, file_path: str) -> tuple:
        """Check code signature of a binary. Returns (signed, signer_name)."""
        system = platform.system()
        try:
            if system == "Darwin":
                result = subprocess.run(
                    ["codesign", "-dvv", file_path],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    for line in result.stderr.split("\n"):
                        if "Authority=" in line:
                            return True, line.split("=", 1)[1].strip()
                return False, ""
            elif system == "Windows":
                result = subprocess.run(
                    ["powershell", "-Command",
                     f"(Get-AuthenticodeSignature '{file_path}').SignerCertificate.Subject"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return True, result.stdout.strip()
                return False, ""
            elif system == "Linux":
                # Check for ELF signature via dpkg-sig or rpm -K
                return False, ""  # Linux binaries often unsigned
        except Exception as e:
            logger.debug("Signature check failed for %s: %s", file_path, e)
        return False, ""

    def _is_internet_download(self, file_path: str) -> bool:
        """Check if file has quarantine attribute (internet download marker)."""
        system = platform.system()
        try:
            if system == "Darwin":
                result = subprocess.run(
                    ["xattr", "-l", file_path], capture_output=True, text=True, timeout=5,
                )
                return "com.apple.quarantine" in result.stdout
            elif system == "Windows":
                # Check Zone.Identifier ADS
                zone_file = file_path + ":Zone.Identifier"
                return os.path.exists(zone_file)
        except Exception:
            pass
        return False

    def _is_temp_path(self, file_path: str) -> bool:
        lower = file_path.lower()
        temp_indicators = ["/tmp/", "\\temp\\", "/var/tmp/", "appdata\\local\\temp"]
        return any(ind in lower for ind in temp_indicators)

    def _check_suspicious_content(self, file_path: str) -> List[str]:
        """Check file content for suspicious patterns (mainly for scripts)."""
        findings = []
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read(65536).lower()  # First 64KB
            for category, patterns in SUSPICIOUS_PATTERNS.items():
                for pattern in patterns:
                    if pattern.lower() in content:
                        findings.append(f"Suspicious content: {category}")
                        break
        except Exception:
            pass
        return findings
