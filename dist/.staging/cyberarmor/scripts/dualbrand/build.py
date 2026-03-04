#!/usr/bin/env python3
"""Dual-brand build tool.

Creates branded distribution zips from a single repo.

Usage:
  python scripts/dualbrand/build.py --brand aishields --out dist/AIShields-oss.zip
  python scripts/dualbrand/build.py --brand cyberarmor --out dist/CyberArmor-commercial.zip
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import zipfile
from pathlib import Path

TEXT_EXTS = {
    ".py", ".md", ".txt", ".yml", ".yaml", ".json", ".toml", ".ini", ".env", ".sh", ".lua", ".js", ".ts", ".tsx", ".jsx", ".html", ".css", ".Dockerfile",
}

# File basenames that are usually text even without an extension
TEXT_BASENAMES = {
    "Dockerfile", "Makefile", "Chart.yaml", "values.yaml", "README", "LICENSE",
}


def is_text_file(path: Path) -> bool:
    if path.name in TEXT_BASENAMES:
        return True
    if path.suffix in TEXT_EXTS:
        return True
    # Helm templates / k8s manifests often have no extension, keep conservative
    if path.parent.name in {"templates"}:
        return True
    return False


def safe_read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except Exception:
        return None
    # quick binary heuristic
    if b"\x00" in data:
        return None
    for enc in ("utf-8", "utf-8-sig"):
        try:
            return data.decode(enc)
        except Exception:
            pass
    return None


def safe_write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def normalize_env_example(text: str, brand: str) -> str:
    """Insert/replace a canonical env block for the chosen brand."""
    if brand == "aishields":
        prefix = "AISHIELDS"
        human = "AIShields"
    else:
        prefix = "CYBERARMOR"
        human = "CyberArmor"

    block = f"""# ===============================
# {human} canonical environment variables
# (The services also accept legacy unprefixed vars for backward compatibility.)
# ===============================
{prefix}_POLICY_API_SECRET=change-me-policy
{prefix}_DETECTION_API_SECRET=change-me-detection
{prefix}_CONTROL_PLANE_URL=http://control-plane:8000
{prefix}_CA_DIR=/etc/{prefix.lower()}/certs
{prefix}_FIPS_MODE=false

"""

    # Remove any previous canonical block (either brand)
    text = re.sub(r"# ===============================\n# (AIShields|CyberArmor) canonical environment variables.*?# ===============================\n.*?\n\n",
                  "",
                  text,
                  flags=re.DOTALL)

    # Prepend block
    return block + text.lstrip()


def apply_replacements(text: str, brand: str) -> str:
    # Header prefix
    if brand == "aishields":
        text = text.replace("x-cyberarmor-", "x-aishields-")
    else:
        text = text.replace("x-aishields-", "x-cyberarmor-")

    # Human-readable product name (conservative replacements)
    if brand == "aishields":
        text = re.sub(r"\bCyberArmor\.ai\b", "AIShields", text)
        text = re.sub(r"\bCyberArmor\b", "AIShields", text)
    else:
        text = re.sub(r"\bAIShields\b", "CyberArmor", text)

    # Paths (keep this narrow to /etc/...)
    if brand == "aishields":
        text = text.replace("/etc/cyberarmor/", "/etc/aishields/")
        text = text.replace("/etc/cyberarmor", "/etc/aishields")
    else:
        text = text.replace("/etc/aishields/", "/etc/cyberarmor/")
        text = text.replace("/etc/aishields", "/etc/cyberarmor")

    return text


def load_branding_surface(repo_root: Path) -> dict:
    """Load the controlled branding surface definition.

    This limits branding changes to a curated set of files/globs + specific
    replacements, avoiding accidental substitutions as the codebase grows.
    """
    surface_path = repo_root / "scripts" / "dualbrand" / "surface.json"
    if not surface_path.exists():
        raise FileNotFoundError(f"Missing branding surface file: {surface_path}")
    return json.loads(surface_path.read_text(encoding="utf-8"))


def render_placeholders(template: str, brand: str) -> str:
    if brand == "aishields":
        ctx = {
            "brand_id": "aishields",
            "brand_name": "AIShields",
            "brand_name_dotai": "AIShields",
            "brand_header": "x-aishields-",
            "brand_prefix": "AISHIELDS_",
            "brand_etc": "/etc/aishields",
            "other_id": "cyberarmor",
            "other_name": "CyberArmor",
            "other_name_dotai": "CyberArmor.ai",
            "other_header": "x-cyberarmor-",
            "other_prefix": "CYBERARMOR_",
            "other_etc": "/etc/cyberarmor",
        }
    else:
        ctx = {
            "brand_id": "cyberarmor",
            "brand_name": "CyberArmor",
            "brand_name_dotai": "CyberArmor.ai",
            "brand_header": "x-cyberarmor-",
            "brand_prefix": "CYBERARMOR_",
            "brand_etc": "/etc/cyberarmor",
            "other_id": "aishields",
            "other_name": "AIShields",
            "other_name_dotai": "AIShields",
            "other_header": "x-aishields-",
            "other_prefix": "AISHIELDS_",
            "other_etc": "/etc/aishields",
        }

    out = template
    for k, v in ctx.items():
        out = out.replace("{{" + k + "}}", v)
    return out


def rewrite_helm_tree(staging: Path, brand: str) -> None:
    helm_dir = staging / "infra" / "helm"
    if not helm_dir.exists():
        return

    aishields = helm_dir / "aishields"
    cyberarmor = helm_dir / "cyberarmor"

    if brand == "cyberarmor":
        # Prefer a dedicated cyberarmor chart if present; otherwise derive from aishields
        if cyberarmor.exists():
            pass
        elif aishields.exists():
            shutil.copytree(aishields, cyberarmor)
        # Optionally remove the aishields chart from commercial dist to reduce confusion
        if aishields.exists():
            shutil.rmtree(aishields)

        # Update Chart.yaml/values/templates within cyberarmor chart
        _rewrite_helm_chart(cyberarmor, brand)

    else:
        # OSS: ensure aishields exists
        if not aishields.exists() and cyberarmor.exists():
            shutil.copytree(cyberarmor, aishields)
        if cyberarmor.exists():
            shutil.rmtree(cyberarmor)
        _rewrite_helm_chart(aishields, brand)


def _rewrite_helm_chart(chart_dir: Path, brand: str) -> None:
    if not chart_dir.exists():
        return

    for p in chart_dir.rglob("*"):
        if p.is_dir():
            continue
        if not is_text_file(p):
            continue
        s = safe_read_text(p)
        if s is None:
            continue

        # Chart metadata
        if p.name == "Chart.yaml":
            if brand == "cyberarmor":
                s = re.sub(r"^name:\s*.*$", "name: cyberarmor", s, flags=re.MULTILINE)
                s = re.sub(r"^description:\s*.*$", "description: CyberArmor.ai Helm chart", s, flags=re.MULTILINE)
            else:
                s = re.sub(r"^name:\s*.*$", "name: aishields", s, flags=re.MULTILINE)
                s = re.sub(r"^description:\s*.*$", "description: AIShields OSS Helm chart", s, flags=re.MULTILINE)

        # Generic replacements
        s = apply_replacements(s, brand)

        # Normalize env var prefixes inside helm values/templates
        if brand == "cyberarmor":
            s = s.replace("AISHIELDS_", "CYBERARMOR_")
        else:
            s = s.replace("CYBERARMOR_", "AISHIELDS_")

        safe_write_text(p, s)


def rewrite_env_example(staging: Path, brand: str) -> None:
    env = staging / "infra" / "docker-compose" / ".env.example"
    if env.exists():
        t = safe_read_text(env)
        if t is not None:
            t = normalize_env_example(t, brand)
            # Also normalize any prefixed vars in the rest of the file
            if brand == "cyberarmor":
                t = t.replace("AISHIELDS_", "CYBERARMOR_")
            else:
                t = t.replace("CYBERARMOR_", "AISHIELDS_")
            safe_write_text(env, t)


def rewrite_controlled_surface(staging: Path, brand: str) -> None:
    """Apply brand rewrites only to a curated set of files.

    This is intentionally *not* a repo-wide text replacement pass.
    """
    repo_root = staging
    surface = load_branding_surface(repo_root)
    targets = surface.get("targets", [])
    if not isinstance(targets, list):
        raise ValueError("surface.json: 'targets' must be a list")

    for t in targets:
        globs = t.get("globs", [])
        if isinstance(globs, str):
            globs = [globs]
        replacements = t.get("replacements", [])
        if not globs or not replacements:
            continue

        # Expand globs
        files: set[Path] = set()
        for g in globs:
            for p in repo_root.glob(g):
                if p.is_file():
                    files.add(p)

        for p in sorted(files):
            if not is_text_file(p):
                continue
            s = safe_read_text(p)
            if s is None:
                continue

            s2 = s
            for r in replacements:
                kind = r.get("kind", "literal")
                frm = render_placeholders(str(r.get("from", "")), brand)
                to = render_placeholders(str(r.get("to", "")), brand)
                if not frm:
                    continue

                if kind == "literal":
                    s2 = s2.replace(frm, to)
                elif kind == "regex":
                    flags = 0
                    if r.get("multiline"):
                        flags |= re.MULTILINE
                    if r.get("dotall"):
                        flags |= re.DOTALL
                    s2 = re.sub(frm, to, s2, flags=flags)
                else:
                    raise ValueError(f"Unknown replacement kind: {kind}")

            if s2 != s:
                safe_write_text(p, s2)


def make_zip(src_dir: Path, out_zip: Path) -> None:
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in src_dir.rglob("*"):
            if p.is_dir():
                continue
            rel = p.relative_to(src_dir)
            z.write(p, rel.as_posix())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--brand", required=True, choices=["aishields", "cyberarmor"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--staging", default="dist/.staging")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    staging_root = repo_root / args.staging
    brand_stage = staging_root / args.brand

    # Recreate staging dir
    if brand_stage.exists():
        shutil.rmtree(brand_stage)
    staging_root.mkdir(parents=True, exist_ok=True)

    def _ignore(dirpath: str, names: list[str]):
        ignore = {".git", "dist", "__pycache__", ".pytest_cache", ".mypy_cache", ".DS_Store"}
        return [n for n in names if n in ignore]

    shutil.copytree(repo_root, brand_stage, ignore=_ignore, dirs_exist_ok=False)

    # Rewrite
    rewrite_env_example(brand_stage, args.brand)
    rewrite_helm_tree(brand_stage, args.brand)
    rewrite_controlled_surface(brand_stage, args.brand)

    # Add a tiny build stamp
    stamp = brand_stage / "BUILD_BRAND.txt"
    stamp.write_text(f"brand={args.brand}\n", encoding="utf-8")

    out_zip = Path(args.out)
    if not out_zip.is_absolute():
        out_zip = (repo_root / out_zip).resolve()

    make_zip(brand_stage, out_zip)
    print(f"Wrote {out_zip}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
