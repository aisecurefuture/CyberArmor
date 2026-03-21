#!/usr/bin/env python3
"""Single-brand guard for CyberArmor packaging surface."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    violations: list[str] = []

    deprecated_paths = [
        ROOT / "scripts" / "dualbrand",
        ROOT / "dist" / "CyberArmor-oss.zip",
        ROOT / "dist" / "CyberArmor-oss-demo-client.zip",
    ]

    for path in deprecated_paths:
        if path.exists():
            violations.append(f"Deprecated dual-brand artifact exists: {path.relative_to(ROOT)}")

    if violations:
        print("Brand surface verification failed:")
        for violation in violations:
            print(f"- {violation}")
        return 1

    print("Brand surface verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
