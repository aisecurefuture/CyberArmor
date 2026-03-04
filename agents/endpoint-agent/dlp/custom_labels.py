"""Custom Classification Label Management.

Allows tenant admins to define custom data classification labels with
regex patterns, severity levels, and manual override capabilities.
"""

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("custom_labels")


@dataclass
class CustomLabel:
    name: str
    description: str = ""
    patterns: List[str] = field(default_factory=list)
    severity: str = "internal"  # public, internal, confidential, restricted, top_secret
    color: str = "#FFA500"
    enabled: bool = True
    tenant_id: str = ""


@dataclass
class ClassificationOverride:
    """Manual override for a specific file or path pattern."""
    path_pattern: str  # glob pattern or exact path
    label: str
    severity: str
    reason: str = ""
    created_by: str = ""
    created_at: str = ""


class CustomLabelManager:
    """Manages custom classification labels synced from control plane.

    Override precedence: manual_override > custom_label_match > auto_classification
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or str(Path.home() / ".aishields" / "custom_labels.db")
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._labels: List[CustomLabel] = []
        self._overrides: Dict[str, ClassificationOverride] = {}
        self._init_db()
        self._load_from_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS custom_labels (
                name TEXT PRIMARY KEY, description TEXT, patterns TEXT,
                severity TEXT, color TEXT, enabled INTEGER, tenant_id TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS overrides (
                path_pattern TEXT PRIMARY KEY, label TEXT, severity TEXT,
                reason TEXT, created_by TEXT, created_at TEXT
            )
        """)
        conn.commit()
        conn.close()

    def _load_from_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            for row in conn.execute("SELECT name, description, patterns, severity, color, enabled, tenant_id FROM custom_labels"):
                self._labels.append(CustomLabel(
                    name=row[0], description=row[1],
                    patterns=json.loads(row[2]) if row[2] else [],
                    severity=row[3], color=row[4], enabled=bool(row[5]),
                    tenant_id=row[6] or "",
                ))
            for row in conn.execute("SELECT path_pattern, label, severity, reason, created_by, created_at FROM overrides"):
                self._overrides[row[0]] = ClassificationOverride(
                    path_pattern=row[0], label=row[1], severity=row[2],
                    reason=row[3], created_by=row[4], created_at=row[5],
                )
            conn.close()
        except Exception as e:
            logger.warning("Failed to load custom labels: %s", e)

    def sync_labels(self, labels: List[dict]):
        """Sync custom labels from control plane."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM custom_labels")
        self._labels = []
        for lbl in labels:
            cl = CustomLabel(
                name=lbl["name"], description=lbl.get("description", ""),
                patterns=lbl.get("patterns", []), severity=lbl.get("severity", "internal"),
                color=lbl.get("color", "#FFA500"), enabled=lbl.get("enabled", True),
                tenant_id=lbl.get("tenant_id", ""),
            )
            self._labels.append(cl)
            conn.execute(
                "INSERT OR REPLACE INTO custom_labels VALUES (?,?,?,?,?,?,?)",
                (cl.name, cl.description, json.dumps(cl.patterns), cl.severity, cl.color, int(cl.enabled), cl.tenant_id),
            )
        conn.commit()
        conn.close()
        logger.info("Synced %d custom labels", len(labels))

    def add_override(self, override: ClassificationOverride):
        """Add a manual classification override for a file/path pattern."""
        override.created_at = datetime.now(timezone.utc).isoformat()
        self._overrides[override.path_pattern] = override
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT OR REPLACE INTO overrides VALUES (?,?,?,?,?,?)",
            (override.path_pattern, override.label, override.severity, override.reason, override.created_by, override.created_at),
        )
        conn.commit()
        conn.close()

    def remove_override(self, path_pattern: str):
        """Remove a manual override."""
        self._overrides.pop(path_pattern, None)
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM overrides WHERE path_pattern=?", (path_pattern,))
        conn.commit()
        conn.close()

    def get_override(self, file_path: str) -> Optional[ClassificationOverride]:
        """Check if a file has a manual override. Uses fnmatch for glob patterns."""
        import fnmatch
        for pattern, override in self._overrides.items():
            if fnmatch.fnmatch(file_path, pattern) or file_path == pattern:
                return override
        return None

    def get_labels(self) -> List[CustomLabel]:
        return [l for l in self._labels if l.enabled]

    def get_labels_as_dicts(self) -> List[dict]:
        return [
            {"name": l.name, "description": l.description, "patterns": l.patterns,
             "severity": l.severity, "color": l.color}
            for l in self.get_labels()
        ]

    def get_all_overrides(self) -> List[ClassificationOverride]:
        return list(self._overrides.values())
