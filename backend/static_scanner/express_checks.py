"""
AegisLab - static_scanner/express_checks.py
===============================================
Static config checks specific to Express.js apps. These look at what
middleware/dependencies are present in the codebase — they do not run the
app. The route-level "possible missing auth" check is explicitly a
low-confidence heuristic (regex can't reliably know what a handler does)
and is reported at INFO severity with a "needs manual review" framing,
never as a confirmed finding.
"""

from __future__ import annotations

import re
from pathlib import Path

from models import Vulnerability, Severity

CORS_WILDCARD_CRED_RE = re.compile(
    r"cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]\*['\"][^}]*credentials\s*:\s*true",
    re.IGNORECASE | re.DOTALL,
)
HELMET_USAGE_RE = re.compile(r"\bhelmet\s*\(")
RATE_LIMIT_USAGE_RE = re.compile(r"\b(rateLimit|expressRateLimit|slowDown)\s*\(")
ROUTE_DEF_RE = re.compile(
    r"\b(?:router|app)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([^)]*)\)",
    re.IGNORECASE,
)
AUTH_NAME_RE = re.compile(r"auth|guard|protect|verify|requireLogin|isAuthenticated|jwt", re.IGNORECASE)
PUBLIC_PATH_RE = re.compile(r"login|signup|register|health|public|webhook|status|ping", re.IGNORECASE)


def run_express_checks(repo_root: Path, files: list[Path], deps: dict) -> list[Vulnerability]:
    findings: list[Vulnerability] = []

    combined_text_chunks = []
    route_findings_count = 0

    for f in files:
        if f.suffix.lower() not in (".js", ".ts", ".mjs", ".cjs"):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        combined_text_chunks.append(text)

        # CORS wildcard + credentials (confirmed pattern, not heuristic)
        if CORS_WILDCARD_CRED_RE.search(text):
            rel = str(f.relative_to(repo_root))
            findings.append(Vulnerability(
                endpoint=rel, method="STATIC", test_module="static_express_config",
                owasp_category="API8:2023 Security Misconfiguration",
                issue="CORS configured with wildcard origin AND credentials: true",
                severity=Severity.CRITICAL,
                description=f"{rel} configures cors() with origin: '*' alongside credentials: true.",
                impact="This combination, where supported, lets any website read authenticated API responses on behalf of a logged-in victim.",
                recommendation="Pass a specific allow-listed origin (or a validation function) instead of '*' whenever credentials are enabled.",
                evidence={"file": rel},
            ))

        # Route-level auth heuristic — capped, clearly labeled low-confidence
        if route_findings_count < 8:
            for m in ROUTE_DEF_RE.finditer(text):
                method, path, handler_args = m.group(1), m.group(2), m.group(3)
                if PUBLIC_PATH_RE.search(path):
                    continue
                if AUTH_NAME_RE.search(handler_args):
                    continue
                rel = str(f.relative_to(repo_root))
                line_no = text[:m.start()].count("\n") + 1
                findings.append(Vulnerability(
                    endpoint=f"{path} ({rel}:{line_no})", method=method.upper(),
                    test_module="static_express_config",
                    owasp_category="API2:2023 Broken Authentication",
                    issue="Route has no obviously-named auth middleware (needs manual review)",
                    severity=Severity.INFO,
                    description=(
                        f"{method.upper()} {path} doesn't reference any handler argument with an "
                        f"auth-like name. This is a low-confidence pattern match, NOT a confirmed finding — "
                        f"the route may use auth applied at the router/app level instead."
                    ),
                    impact="If this route is genuinely unprotected, it may expose data or actions that should require authentication.",
                    recommendation="Manually confirm this route is covered by authentication middleware (directly or via router.use()), or run AegisLab's live auth_tests module against the running API for a confirmed result.",
                    evidence={"file": rel, "line": line_no},
                ))
                route_findings_count += 1
                if route_findings_count >= 8:
                    break

    full_text = "\n".join(combined_text_chunks)
    has_helmet_dep = "helmet" in deps
    has_helmet_usage = bool(HELMET_USAGE_RE.search(full_text))
    has_rl_dep = "express-rate-limit" in deps
    has_rl_usage = bool(RATE_LIMIT_USAGE_RE.search(full_text))

    if not (has_helmet_dep or has_helmet_usage):
        findings.append(Vulnerability(
            endpoint="(project-wide)", method="STATIC", test_module="static_express_config",
            owasp_category="API8:2023 Security Misconfiguration",
            issue="No helmet() security-headers middleware detected",
            severity=Severity.MEDIUM,
            description="Neither a 'helmet' dependency nor a helmet() call was found anywhere in the scanned source.",
            impact="Without helmet (or equivalent), the app likely won't send standard hardening headers (CSP, X-Content-Type-Options, X-Frame-Options, HSTS).",
            recommendation="Run `npm install helmet` and add `app.use(helmet())` near the top of your Express app setup.",
            evidence={},
        ))

    if not (has_rl_dep or has_rl_usage):
        findings.append(Vulnerability(
            endpoint="(project-wide)", method="STATIC", test_module="static_express_config",
            owasp_category="API4:2023 Unrestricted Resource Consumption",
            issue="No rate-limiting middleware detected in source",
            severity=Severity.MEDIUM,
            description="Neither an 'express-rate-limit' dependency nor a rate-limit middleware call was found in the scanned source.",
            impact="Without rate limiting, sensitive endpoints (login, password reset, OTP) are exposed to brute-force and credential-stuffing attacks.",
            recommendation="Run `npm install express-rate-limit` and apply it to sensitive routes, e.g. `app.use('/auth/login', rateLimit({ windowMs: 60_000, max: 10 }))`.",
            evidence={},
        ))

    return findings
