"""
AegisLab - static_scanner/nestjs_checks.py
==============================================
Static config checks specific to NestJS apps: global ValidationPipe,
@nestjs/throttler usage, and helmet — the three most common
"forgot to wire this up" gaps in real NestJS projects.
"""

from __future__ import annotations

from pathlib import Path

from models import Vulnerability, Severity


def run_nestjs_checks(repo_root: Path, files: list[Path], deps: dict) -> list[Vulnerability]:
    findings: list[Vulnerability] = []

    main_ts_candidates = [f for f in files if f.name == "main.ts"]
    full_main_text = ""
    for f in main_ts_candidates:
        try:
            full_main_text += f.read_text(encoding="utf-8", errors="ignore") + "\n"
        except Exception:
            continue

    # Fall back to scanning everything if no main.ts was found/extracted
    search_text = full_main_text
    if not search_text:
        for f in files:
            if f.suffix.lower() == ".ts":
                try:
                    search_text += f.read_text(encoding="utf-8", errors="ignore") + "\n"
                except Exception:
                    continue

    if "useGlobalPipes" not in search_text or "ValidationPipe" not in search_text:
        findings.append(Vulnerability(
            endpoint="(project-wide)", method="STATIC", test_module="static_nestjs_config",
            owasp_category="A03:2021 Injection",
            issue="No global ValidationPipe detected",
            severity=Severity.MEDIUM,
            description="No call to app.useGlobalPipes(new ValidationPipe(...)) was found in main.ts (or anywhere scanned).",
            impact="Without a global ValidationPipe, incoming request bodies aren't automatically validated against your DTOs, increasing the risk of malformed/malicious input reaching business logic.",
            recommendation="In main.ts: `app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))`.",
            evidence={},
        ))

    if "@nestjs/throttler" not in deps and "ThrottlerModule" not in search_text:
        findings.append(Vulnerability(
            endpoint="(project-wide)", method="STATIC", test_module="static_nestjs_config",
            owasp_category="API4:2023 Unrestricted Resource Consumption",
            issue="No @nestjs/throttler rate limiting detected",
            severity=Severity.MEDIUM,
            description="Neither a '@nestjs/throttler' dependency nor a ThrottlerModule import was found in the scanned source.",
            impact="Without rate limiting, sensitive endpoints are exposed to brute-force and resource-exhaustion attacks.",
            recommendation="Run `npm install @nestjs/throttler` and register ThrottlerModule in your root AppModule, applying ThrottlerGuard globally or per-route.",
            evidence={},
        ))

    if "helmet" not in deps and "helmet(" not in search_text:
        findings.append(Vulnerability(
            endpoint="(project-wide)", method="STATIC", test_module="static_nestjs_config",
            owasp_category="API8:2023 Security Misconfiguration",
            issue="No helmet() security-headers middleware detected",
            severity=Severity.MEDIUM,
            description="Neither a 'helmet' dependency nor a helmet() call was found in the scanned source.",
            impact="Without helmet, the app likely won't send standard hardening headers (CSP, X-Content-Type-Options, HSTS, etc.).",
            recommendation="Run `npm install helmet` and add `app.use(helmet())` in main.ts, before any route registration.",
            evidence={},
        ))

    return findings
