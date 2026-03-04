"""Content Scanner for CyberArmor.ai Endpoint Agent.

Scans file contents, clipboard data, and form inputs for sensitive data.
Integrates with DataClassifier for classification and reports findings.
"""

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from .classifier import DataClassifier, ClassificationResult

logger = logging.getLogger("dlp_scanner")


@dataclass
class ScanResult:
    path: str
    classification: ClassificationResult
    scanned_at: float = field(default_factory=time.time)
    file_hash: str = ""
    file_size: int = 0


class ContentScanner:
    """Scans files and content for sensitive data with incremental support."""

    def __init__(self, classifier: Optional[DataClassifier] = None):
        self.classifier = classifier or DataClassifier()
        self._scan_cache: Dict[str, ScanResult] = {}
        self._file_hashes: Dict[str, str] = {}

    def scan_file(self, file_path: str, force: bool = False) -> Optional[ScanResult]:
        """Scan a single file. Uses incremental scanning (skip unchanged files)."""
        try:
            path = Path(file_path)
            if not path.exists() or not path.is_file():
                return None

            stat = path.stat()
            file_size = stat.st_size
            if file_size > 50 * 1024 * 1024:  # Skip files > 50MB
                logger.debug("Skipping large file: %s (%d bytes)", file_path, file_size)
                return None

            # Incremental: check if file changed since last scan
            if not force and file_path in self._scan_cache:
                cached = self._scan_cache[file_path]
                if stat.st_mtime <= cached.scanned_at:
                    return cached

            # Compute hash for change detection
            file_hash = self._quick_hash(file_path, file_size)
            if not force and file_hash == self._file_hashes.get(file_path):
                return self._scan_cache.get(file_path)

            classification = self.classifier.classify_file(file_path)
            result = ScanResult(
                path=file_path,
                classification=classification,
                file_hash=file_hash,
                file_size=file_size,
            )

            self._scan_cache[file_path] = result
            self._file_hashes[file_path] = file_hash
            return result

        except PermissionError:
            logger.debug("Permission denied scanning: %s", file_path)
            return None
        except Exception as e:
            logger.warning("Scan error for %s: %s", file_path, e)
            return None

    def scan_directory(
        self, directory: str, extensions: Optional[Set[str]] = None, max_files: int = 10000,
    ) -> List[ScanResult]:
        """Scan all files in a directory recursively."""
        results = []
        count = 0
        default_extensions = {
            ".txt", ".csv", ".json", ".xml", ".yaml", ".yml", ".md",
            ".py", ".js", ".ts", ".java", ".cs", ".go", ".rs", ".rb", ".php",
            ".env", ".cfg", ".conf", ".ini", ".properties",
            ".sql", ".sh", ".bat", ".ps1",
            ".pem", ".key", ".crt", ".p12",
            ".doc", ".docx", ".xls", ".xlsx", ".pdf",
        }
        exts = extensions or default_extensions

        for root, dirs, files in os.walk(directory):
            # Skip hidden directories and common non-useful dirs
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in {"node_modules", "__pycache__", ".git", "venv"}]
            for fname in files:
                if count >= max_files:
                    break
                ext = os.path.splitext(fname)[1].lower()
                if ext in exts:
                    result = self.scan_file(os.path.join(root, fname))
                    if result and result.classification.level != "public":
                        results.append(result)
                    count += 1

        logger.info("Scanned %d files in %s, found %d with sensitive data", count, directory, len(results))
        return results

    def scan_text(self, text: str, source: str = "clipboard") -> ClassificationResult:
        """Scan arbitrary text content (clipboard, form data, etc.)."""
        return self.classifier.classify_text(text)

    def scan_clipboard(self) -> Optional[ClassificationResult]:
        """Scan current clipboard contents for sensitive data."""
        try:
            import subprocess
            import platform
            system = platform.system()
            if system == "Darwin":
                result = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=5)
                text = result.stdout
            elif system == "Linux":
                result = subprocess.run(["xclip", "-selection", "clipboard", "-o"], capture_output=True, text=True, timeout=5)
                text = result.stdout
            elif system == "Windows":
                import ctypes
                # Windows clipboard access
                ctypes.windll.user32.OpenClipboard(0)
                try:
                    handle = ctypes.windll.user32.GetClipboardData(1)  # CF_TEXT
                    text = ctypes.c_char_p(handle).value.decode("utf-8", errors="ignore") if handle else ""
                finally:
                    ctypes.windll.user32.CloseClipboard()
            else:
                return None

            if text and len(text) > 3:
                return self.scan_text(text, source="clipboard")
        except Exception as e:
            logger.debug("Clipboard scan failed: %s", e)
        return None

    def get_scan_summary(self) -> Dict:
        """Get summary of all scanned files and findings."""
        levels = {"public": 0, "internal": 0, "confidential": 0, "restricted": 0, "top_secret": 0}
        for result in self._scan_cache.values():
            level = result.classification.level
            levels[level] = levels.get(level, 0) + 1
        return {
            "total_files_scanned": len(self._scan_cache),
            "findings_by_level": levels,
            "last_scan": max((r.scanned_at for r in self._scan_cache.values()), default=0),
        }

    def _quick_hash(self, file_path: str, file_size: int) -> str:
        """Quick hash using first/last 4KB + file size for change detection."""
        h = hashlib.sha256()
        h.update(str(file_size).encode())
        try:
            with open(file_path, "rb") as f:
                h.update(f.read(4096))
                if file_size > 8192:
                    f.seek(-4096, 2)
                    h.update(f.read(4096))
        except Exception:
            pass
        return h.hexdigest()[:16]
