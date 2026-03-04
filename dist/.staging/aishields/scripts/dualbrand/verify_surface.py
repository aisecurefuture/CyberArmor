#!/usr/bin/env python3
"""Verify that brand-specific identifiers only appear inside the approved branding surface.

This prevents repo drift as the codebase grows (e.g., accidental commits of
x-aishields-* headers into core libraries).

Run:
  python3 scripts/dualbrand/verify_surface.py
or:
  make verify-brand-surface
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SURFACE = ROOT / "scripts" / "dualbrand" / "surface.json"

BRAND_TOKENS = [
    r"x-aishields-",
    r"x-cyberarmor-",
    r"AISHIELDS_",
    r"CYBERARMOR_",
    r"/etc/aishields",
    r"/etc/cyberarmor",
]

# Always-allowed locations (build scripts, CI files)
ALWAYS_ALLOWED_GLOBS = [
    "scripts/dualbrand/**",
    ".github/**",
]


def _is_text(path: Path) -> bool:
    if path.is_symlink():
        return False
    # treat small-ish files as text-ish; skip obvious binaries
    try:
        data = path.read_bytes()
    except Exception:
        return False
    if b"\x00" in data:
        return False
    return True


def _load_surface_globs() -> list[str]:
    try:
        surface = json.loads(SURFACE.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"ERROR: could not read {SURFACE}: {e}")
        return []

    targets = surface.get("targets", [])
    globs: list[str] = []
    if isinstance(targets, list):
        for t in targets:
            gs = t.get("globs", [])
            if isinstance(gs, str):
                globs.append(gs)
            elif isinstance(gs, list):
                globs.extend([g for g in gs if isinstance(g, str)])
    return globs


def _path_matches_any(repo_rel: Path, globs: list[str]) -> bool:
    """Match repo-relative paths against surface globs.

    We intentionally use fnmatch on POSIX strings because Path.match has
    surprising edge-cases with ** patterns.
    """
    import fnmatch

    rel = repo_rel.as_posix()
    for g in globs:
        if fnmatch.fnmatchcase(rel, g):
            return True
    return False



def main() -> int:
    surface_globs = _load_surface_globs()
    allowed_globs = ALWAYS_ALLOWED_GLOBS + surface_globs

    violations: list[tuple[str, str]] = []

    for p in ROOT.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(ROOT)

        # Skip dist/staging artifacts if present
        if rel.parts and (rel.parts[0] in {"dist", ".git", "__pycache__"} or rel.parts[0].startswith("Archive")):
            continue

        if not _is_text(p):
            continue

        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for token in BRAND_TOKENS:
            if re.search(token, text):
                if not _path_matches_any(rel, allowed_globs):
                    violations.append((str(rel), token))

    if violations:
        print("Brand surface violations detected. These files contain brand-specific tokens but are not in surface.json allowlist:\n")
        for rel, tok in violations:
            print(f"- {rel}  (matched: {tok})")
        print("\nFix by either:\n  1) moving the token behind placeholders and adding the file glob to scripts/dualbrand/surface.json, or\n  2) removing the token from the core file (preferred).")
        return 1

    print("Brand surface verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
