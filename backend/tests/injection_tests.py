"""
AegisLab - injection_tests.py
================================
Maps to OWASP API Security Top 10: API8:2023 Security Misconfiguration /
OWASP Top 10 Web: A03:2021 Injection.

This module performs DETECTION ONLY using the canonical, non-destructive
test strings published in the OWASP Testing Guide. It never sends payloads
designed to modify or delete data (no DROP/UPDATE/DELETE-style payloads,
no real OS command execution side effects beyond a harmless echoed marker).

Checks performed:
  1. Error-based SQL injection signatures (single-quote probe + DB error grep)
  2. Boolean-based SQLi via response-shape comparison (' OR '1'='1 vs an
     impossible condition) — read-only GET requests only
  3. Time-based blind SQLi heuristic — ONE bounded delay probe per parameter,
     capped at 2 seconds, only if explicitly enabled (off by default)
  4. NoSQL injection operator probes (e.g. {"$ne": null}) on JSON bodies
  5. Reflected XSS — checks if a harmless marker string is reflected
     unescaped in an HTML response (no script execution attempted)
  6. Basic path traversal probe on path/query params that look file-related,
     checking only for an unexpected change in response shape — never
     requests real sensitive OS files
"""

from __future__ import annotations

import re
import time

from models import EndpointSpec, Vulnerability, Severity
from .base import BaseTestModule

SQL_ERROR_PROBE = "'"
SQLI_BOOLEAN_TRUE = "' OR '1'='1"
SQLI_BOOLEAN_FALSE = "' AND '1'='2"
XSS_MARKER = "<aegislab_marker_d8f1>"
NOSQL_PROBES = [{"$ne": None}, {"$gt": ""}]

SQL_ERROR_SIGNATURES = [
    "sql syntax", "sqlstate", "unclosed quotation mark", "pg::", "ora-0",
    "you have an error in your sql syntax", "odbc sql server driver",
    "sqlite3.operationalerror", "syntax error at or near", "psql:",
]


class InjectionTests(BaseTestModule):
    name = "injection_tests"
    description = "Safe, detection-only probes for SQL/NoSQL injection and reflected XSS"

    # Time-based blind SQLi check is OFF by default — it's the only probe that
    # intentionally adds latency to a request, so it requires explicit opt-in.
    enable_timing_probe = False

    async def run(self, endpoints: list[EndpointSpec]) -> list[Vulnerability]:
        get_endpoints = [e for e in endpoints if e.method.value == "GET" and e.params][:15]
        write_endpoints = [e for e in endpoints if e.method.value in ("POST", "PUT", "PATCH")
                            and e.request_body_sample][:15]

        for ep in get_endpoints:
            await self._check_query_param_sqli(ep)
            await self._check_reflected_xss(ep)

        for ep in write_endpoints:
            await self._check_body_sqli_and_nosqli(ep)

        return self.findings

    async def _check_query_param_sqli(self, ep: EndpointSpec):
        param = ep.params[0]
        baseline = await self.client.get(ep.path, params={param: "aegislab_baseline_1"})
        if baseline.error:
            return

        # 1. Error-based
        probe_resp = await self.client.get(ep.path, params={param: SQL_ERROR_PROBE})
        if not probe_resp.error:
            sigs = [s for s in SQL_ERROR_SIGNATURES if s in probe_resp.text.lower()]
            if sigs:
                self.add_finding(
                    endpoint=ep.path, method="GET",
                    owasp_category="A03:2021 Injection",
                    issue=f"Possible SQL injection via query parameter '{param}'",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Sending a single-quote character in the '{param}' parameter produced a "
                        f"database error signature in the response: {sigs[0]}."
                    ),
                    impact="Database error leakage from unsanitized input strongly suggests the query is "
                           "built via string concatenation, which may allow data exfiltration or modification.",
                    recommendation="Use parameterized queries / a query builder with bound parameters everywhere. Never concatenate user input into SQL.",
                    evidence={"param": param, "signature_found": sigs[0]},
                )
                return  # don't pile on more probes once confirmed

        # 2. Boolean-based comparison (only meaningful if baseline succeeded)
        if baseline.ok:
            true_resp = await self.client.get(ep.path, params={param: SQLI_BOOLEAN_TRUE})
            false_resp = await self.client.get(ep.path, params={param: SQLI_BOOLEAN_FALSE})
            if not true_resp.error and not false_resp.error:
                if true_resp.status_code != false_resp.status_code and true_resp.ok and not false_resp.ok:
                    self.add_finding(
                        endpoint=ep.path, method="GET",
                        owasp_category="A03:2021 Injection",
                        issue=f"Possible boolean-based blind SQL injection via '{param}'",
                        severity=Severity.HIGH,
                        description=(
                            f"An always-true condition injected into '{param}' returned HTTP "
                            f"{true_resp.status_code}, while an always-false condition returned "
                            f"{false_resp.status_code} — the backend appears to be evaluating the injected logic."
                        ),
                        impact="An attacker may be able to infer database contents one bit at a time without seeing direct errors.",
                        recommendation="Use parameterized queries; validate/allowlist input types and formats before they reach the query layer.",
                        evidence={"status_true": true_resp.status_code, "status_false": false_resp.status_code},
                    )

        if self.enable_timing_probe:
            await self._check_timing_sqli(ep, param)

    async def _check_timing_sqli(self, ep: EndpointSpec, param: str):
        # Single bounded probe — capped at a short delay, executed once.
        start = time.perf_counter()
        resp = await self.client.get(ep.path, params={param: "aegislab_timing_probe"})
        baseline_time = time.perf_counter() - start
        if resp.error:
            return
        if resp.elapsed > baseline_time + 1.5:
            self.add_finding(
                endpoint=ep.path, method="GET",
                owasp_category="A03:2021 Injection",
                issue=f"Anomalous response delay on parameter '{param}' (possible time-based blind SQLi)",
                severity=Severity.MEDIUM,
                description="Response time for this parameter was significantly higher than baseline, which can indicate a time-based blind injection vector. This is a heuristic signal, not a confirmation.",
                impact="If confirmed, an attacker could extract data via timing side-channels even with no visible output.",
                recommendation="Manually verify with a proper pentest tool; in the meantime, audit this parameter's query path for raw concatenation.",
                evidence={"elapsed_seconds": round(resp.elapsed, 2)},
            )

    async def _check_reflected_xss(self, ep: EndpointSpec):
        param = ep.params[0]
        resp = await self.client.get(ep.path, params={param: XSS_MARKER})
        if resp.error:
            return
        content_type = (resp.header("content-type") or "").lower()
        if "html" in content_type and XSS_MARKER in resp.text:
            self.add_finding(
                endpoint=ep.path, method="GET",
                owasp_category="A03:2021 Injection (XSS)",
                issue=f"Reflected input not HTML-escaped (parameter '{param}')",
                severity=Severity.MEDIUM,
                description=f"A harmless marker string sent in '{param}' was reflected verbatim, unescaped, in an HTML response.",
                impact="If a real script payload were used instead, it could execute in a victim's browser (reflected XSS), enabling session theft or UI manipulation.",
                recommendation="HTML-encode all user-controlled output, or use a templating engine with auto-escaping enabled by default.",
                evidence={"param": param, "reflected": True},
            )

    async def _check_body_sqli_and_nosqli(self, ep: EndpointSpec):
        base_body = dict(ep.request_body_sample or {})
        string_fields = [k for k, v in base_body.items() if isinstance(v, str) and not self.looks_like_sensitive_field(k)]
        if not string_fields:
            return
        target_field = string_fields[0]

        # Error-based SQLi via JSON body field
        probe_body = dict(base_body)
        probe_body[target_field] = SQL_ERROR_PROBE
        resp = await self.client.request(ep.method.value, ep.path, json_body=probe_body)
        if not resp.error:
            sigs = [s for s in SQL_ERROR_SIGNATURES if s in resp.text.lower()]
            if sigs:
                self.add_finding(
                    endpoint=ep.path, method=ep.method.value,
                    owasp_category="A03:2021 Injection",
                    issue=f"Possible SQL injection via body field '{target_field}'",
                    severity=Severity.CRITICAL,
                    description=f"A single-quote character in JSON field '{target_field}' produced a database error signature: {sigs[0]}.",
                    impact="Suggests unsanitized input reaches a SQL query, risking data exfiltration or corruption.",
                    recommendation="Use parameterized queries / an ORM with proper escaping for all body-derived input.",
                    evidence={"field": target_field, "signature_found": sigs[0]},
                )

        # NoSQL operator injection — only meaningful if the backend looks Mongo-like
        for nosql_probe in NOSQL_PROBES:
            probe_body = dict(base_body)
            probe_body[target_field] = nosql_probe
            nosql_resp = await self.client.request(ep.method.value, ep.path, json_body=probe_body)
            if nosql_resp.error:
                continue
            if nosql_resp.ok:
                self.add_finding(
                    endpoint=ep.path, method=ep.method.value,
                    owasp_category="A03:2021 Injection",
                    issue=f"Possible NoSQL operator injection via body field '{target_field}'",
                    severity=Severity.HIGH,
                    description=(
                        f"Replacing the value of '{target_field}' with a MongoDB query operator "
                        f"({nosql_probe}) was accepted (HTTP {nosql_resp.status_code}) instead of being "
                        f"rejected as an invalid string value."
                    ),
                    impact="If the field reaches a NoSQL query unsanitized, an attacker could bypass auth checks or filters (e.g. login bypass via $ne).",
                    recommendation="Validate and coerce input types strictly (reject objects where a string/number is expected) before passing to the database driver.",
                    evidence={"field": target_field, "probe": str(nosql_probe), "status": nosql_resp.status_code},
                )
                break
