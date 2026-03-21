#!/usr/bin/env python3
"""CyberArmor distribution builder.

Creates a single CyberArmor distribution zip from the repository.
"""

from __future__ import annotations

import argparse
import shutil
import zipfile
from pathlib import Path


def make_zip(src_dir: Path, out_zip: Path) -> None:
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in src_dir.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(src_dir).as_posix())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--brand", default="cyberarmor", choices=["cyberarmor"])
    parser.add_argument("--out", required=True)
    parser.add_argument("--staging", default="dist/.staging")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    staging_root = (repo_root / args.staging).resolve()
    stage_dir = staging_root / args.brand

    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    staging_root.mkdir(parents=True, exist_ok=True)

    def _ignore(_dirpath: str, names: list[str]) -> list[str]:
        ignored = {
            ".git",
            "dist",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".DS_Store",
        }
        return [name for name in names if name in ignored]

    shutil.copytree(repo_root, stage_dir, ignore=_ignore)
    (stage_dir / "BUILD_BRAND.txt").write_text(f"brand={args.brand}\n", encoding="utf-8")

    out_zip = Path(args.out)
    if not out_zip.is_absolute():
        out_zip = (repo_root / out_zip).resolve()

    make_zip(stage_dir, out_zip)
    print(f"Wrote {out_zip}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
