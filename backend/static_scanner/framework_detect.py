"""
AegisLab - static_scanner/framework_detect.py
=================================================
Lightweight framework detection from package.json dependencies, so the
scanner only runs framework-specific checks that are actually relevant.
"""

from __future__ import annotations

import json
from pathlib import Path


def detect_frameworks(repo_root: Path) -> dict:
    """Returns flags + the parsed dependency set from the first package.json found."""
    result = {"express": False, "nestjs": False, "supabase": False, "dependencies": {}}

    pkg_files = list(repo_root.rglob("package.json"))
    # Prefer a root-level package.json if multiple exist (skip ones inside skipped dirs —
    # extractor.py already filtered node_modules etc., so this is just picking the shallowest).
    pkg_files.sort(key=lambda p: len(p.parts))

    for pkg_file in pkg_files[:5]:
        try:
            data = json.loads(pkg_file.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        result["dependencies"].update(deps)

        if "express" in deps:
            result["express"] = True
        if "@nestjs/core" in deps:
            result["nestjs"] = True
        if "@supabase/supabase-js" in deps or "supabase" in deps:
            result["supabase"] = True

    return result
