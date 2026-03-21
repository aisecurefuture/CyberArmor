#!/usr/bin/env python3
"""Fail CI if dual-brand packaging artifacts/config reappear."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    violations: list[str] = []

    if (ROOT / "dist/.staging/cyberarmor").exists():
        violations.append("Legacy staging directory exists: dist/.staging/cyberarmor")

    makefile = ROOT / "Makefile"
    if makefile.exists():
        text = makefile.read_text(encoding="utf-8", errors="ignore")
        banned_markers = ["dist-oss", "CyberArmor-oss.zip"]
        for marker in banned_markers:
            if marker in text:
                violations.append(f"Makefile still contains deprecated dual-brand marker: {marker}")

    dualbrand_readme = ROOT / "scripts/branding/README.md"
    if dualbrand_readme.exists():
        text = dualbrand_readme.read_text(encoding="utf-8", errors="ignore")
        banned_markers = ["CyberArmor (OSS)", "dist/CyberArmor-oss.zip", "make dist-oss"]
        for marker in banned_markers:
            if marker in text:
                violations.append(f"scripts/branding/README.md contains deprecated marker: {marker}")

    if violations:
        print("CyberArmor single-brand guard failed:")
        for item in violations:
            print(f"- {item}")
        return 1

    print("CyberArmor single-brand guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
