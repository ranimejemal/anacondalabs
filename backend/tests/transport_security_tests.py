"""
AegisLab - transport_security_tests.py
==========================================
Maps to OWASP API Security Top 10: API8:2023 Security Misconfiguration, and
OWASP Top 10 Web: A02:2021 Cryptographic Failures.

Checks performed (read-only, non-destructive):
  1. Base URL uses HTTP instead of HTTPS
  2. HSTS header (Strict-Transport-Security) missing
  3. Missing common security headers (X-Content-Type-Options, X-Frame-Options,
     Content-Security-Policy)
  4. Cookies missing Secure / HttpOnly / SameSite attributes
  5. TLS handshake inspection: negotiated protocol version (flags legacy
     TLS 1.0/1.1 or SSLv3) — a standard handshake only, no certificate
     tampering or MITM behavior of any kind
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from urllib.parse import urlparse

from models import EndpointSpec, Vulnerability, Severity
from .base import BaseTestModule

WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


class TransportSecurityTests(BaseTestModule):
    name = "transport_security_tests"
    description = "HTTPS enforcement, security headers, cookie flags, and TLS version checks"

    async def run(self, endpoints: list[EndpointSpec]) -> list[Vulnerability]:
        parsed = urlparse(self.client.base_url)

        if parsed.scheme == "http":
            self.add_finding(
                endpoint="(base URL)", method="N/A",
                owasp_category="A02:2021 Cryptographic Failures",
                issue="API base URL uses unencrypted HTTP",
                severity=Severity.CRITICAL,
                description=f"The configured base URL ({self.client.base_url}) uses http:// rather than https://.",
                impact="All traffic — including bearer tokens and request/response bodies — travels in plaintext and can be intercepted or modified in transit.",
                recommendation="Serve the API exclusively over HTTPS/TLS 1.2+ and redirect all HTTP traffic to HTTPS.",
                evidence={"base_url": self.client.base_url},
            )
            return self.findings  # no point checking HSTS/TLS version on a plaintext target

        sample_endpoints = endpoints[:5] or [EndpointSpec(path="/", method="GET", requires_auth=False)]
        checked_headers = False
        for ep in sample_endpoints:
            resp = await self.client.get(ep.path)
            if resp.error or resp.status_code == 0:
                continue
            if not checked_headers:
                self._check_security_headers(ep, resp)
                self._check_cookies(ep, resp)
                checked_headers = True
                break

        await self._check_tls_version(parsed.hostname or "", parsed.port or 443)

        return self.findings

    def _check_security_headers(self, ep: EndpointSpec, resp):
        if not resp.header("strict-transport-security"):
            self.add_finding(
                endpoint=ep.path, method="GET",
                owasp_category="A02:2021 Cryptographic Failures",
                issue="Missing Strict-Transport-Security (HSTS) header",
                severity=Severity.MEDIUM,
                description="The response does not include a Strict-Transport-Security header.",
                impact="Without HSTS, browsers may be tricked (e.g. via downgrade attacks on a shared network) into connecting over plain HTTP at least once, exposing credentials.",
                recommendation='Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` at the web server/proxy level.',
                evidence={},
            )

        missing = []
        if not resp.header("x-content-type-options"):
            missing.append("X-Content-Type-Options")
        if not resp.header("x-frame-options") and not resp.header("content-security-policy"):
            missing.append("X-Frame-Options or CSP frame-ancestors")
        if not resp.header("content-security-policy"):
            missing.append("Content-Security-Policy")

        if missing:
            self.add_finding(
                endpoint=ep.path, method="GET",
                owasp_category="API8:2023 Security Misconfiguration",
                issue="Missing recommended security headers",
                severity=Severity.LOW,
                description=f"The response is missing: {', '.join(missing)}.",
                impact="These headers provide defense-in-depth against MIME-sniffing, clickjacking, and injected content execution.",
                recommendation="Add the missing headers via middleware (e.g. helmet.js for Express/NestJS) at the application or proxy level.",
                evidence={"missing_headers": missing},
            )

    def _check_cookies(self, ep: EndpointSpec, resp):
        set_cookie = resp.header("set-cookie")
        if not set_cookie:
            return
        cookie_lower = set_cookie.lower()
        problems = []
        if "secure" not in cookie_lower:
            problems.append("Secure")
        if "httponly" not in cookie_lower:
            problems.append("HttpOnly")
        if "samesite" not in cookie_lower:
            problems.append("SameSite")

        if problems:
            self.add_finding(
                endpoint=ep.path, method="GET",
                owasp_category="A02:2021 Cryptographic Failures",
                issue=f"Session cookie missing attribute(s): {', '.join(problems)}",
                severity=Severity.MEDIUM,
                description=f"A Set-Cookie header was observed without: {', '.join(problems)}.",
                impact="Missing Secure/HttpOnly/SameSite increases exposure to cookie theft via XSS, network interception, or CSRF.",
                recommendation="Set cookies with `Secure; HttpOnly; SameSite=Strict` (or Lax, if cross-site flows are required).",
                evidence={"missing_attributes": problems},
            )

    async def _check_tls_version(self, hostname: str, port: int):
        if not hostname:
            return
        try:
            version = await asyncio.to_thread(self._get_tls_version_sync, hostname, port)
        except Exception:
            return
        if version and version in WEAK_TLS_VERSIONS:
            self.add_finding(
                endpoint="(TLS handshake)", method="N/A",
                owasp_category="A02:2021 Cryptographic Failures",
                issue=f"Server negotiates a legacy/weak TLS version ({version})",
                severity=Severity.HIGH,
                description=f"A standard TLS handshake against {hostname}:{port} negotiated {version}.",
                impact="Legacy TLS versions have known cryptographic weaknesses and are deprecated by major browsers and PCI-DSS.",
                recommendation="Disable TLS versions below 1.2 on the server/load balancer; require TLS 1.2 or, ideally, TLS 1.3.",
                evidence={"negotiated_version": version},
            )

    @staticmethod
    def _get_tls_version_sync(hostname: str, port: int) -> str | None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we only inspect the handshake, not validate the chain
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                return tls_sock.version()
