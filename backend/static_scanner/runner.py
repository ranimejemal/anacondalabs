"""
AegisLab - static_scanner/runner.py
=======================================
Orchestrates a full static scan: safely extract → detect framework(s) →
run secret scan (always) + framework-specific config checks → return
findings in the same Vulnerability schema the dynamic engine uses, so the
dashboard can render both with the same UI components.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from models import Vulnerability
from .extractor import safe_extract, ZipRejectedError
from .framework_detect import detect_frameworks
from .secret_scan import scan_file_for_secrets
from .express_checks import run_express_checks
from .nestjs_checks import run_nestjs_checks

MAX_FILES_TO_SECRET_SCAN = 4000  # safety cap even after extraction filtering


def scan_zip(zip_path: str) -> dict:
    """
    Returns:
        {
          "frameworks_detected": [...],
          "files_scanned": int,
          "findings": [Vulnerability, ...],
        }
    Raises ZipRejectedError if the archive fails safety checks.
    """
    with tempfile.TemporaryDirectory(prefix="aegislab_static_") as tmp:
        tmp_path = Path(tmp)
        files = safe_extract(zip_path, tmp)

        frameworks = detect_frameworks(tmp_path)
        findings: list[Vulnerability] = []

        # 1. Secret scan — runs on every extracted file, regardless of framework.
        for f in files[:MAX_FILES_TO_SECRET_SCAN]:
            findings.extend(scan_file_for_secrets(f, tmp_path))

        # 2. Framework-specific config checks
        detected_names = []
        if frameworks["express"]:
            detected_names.append("express")
            findings.extend(run_express_checks(tmp_path, files, frameworks["dependencies"]))
        if frameworks["nestjs"]:
            detected_names.append("nestjs")
            findings.extend(run_nestjs_checks(tmp_path, files, frameworks["dependencies"]))
        if frameworks["supabase"]:
            detected_names.append("supabase")
            # Supabase-specific risk is already covered by the service_role
            # key check in secret_scan.py — no extra module needed here.

        if not detected_names:
            detected_names.append("unrecognized (ran secret scan only)")

        return {
            "frameworks_detected": detected_names,
            "files_scanned": len(files),
            "findings": findings,
        }
