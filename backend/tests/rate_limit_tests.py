"""
AegisLab - rate_limit_tests.py
=================================
Maps to OWASP API Security Top 10: API4:2023 Unrestricted Resource Consumption.

Checks performed:
  1. Sends a small, capped burst of requests to sensitive endpoints
     (login, password reset, OTP, search) and checks whether the server
     ever responds with 429 / Retry-After. Burst size is capped low
     (default 20 requests) and the burst stops immediately the moment
     a 429 is observed — so this test is itself rate-limit-safe and will
     never hammer a live system.
  2. Checks for the presence of standard rate-limit response headers
     (X-RateLimit-*, RateLimit-*, Retry-After) as a softer signal even
     when no 429 was triggered.
"""

from __future__ import annotations

import asyncio
import re

from models import EndpointSpec, Vulnerability, Severity
from .base import BaseTestModule

SENSITIVE_PATTERN = re.compile(r"login|signin|auth|password|reset|otp|verify|register|signup", re.IGNORECASE)
MAX_BURST = 20


class RateLimitTests(BaseTestModule):
    name = "rate_limit_tests"
    description = "Burst-request probing (capped & self-limiting) for missing rate limits on sensitive endpoints"

    async def run(self, endpoints: list[EndpointSpec]) -> list[Vulnerability]:
        sensitive = [e for e in endpoints if SENSITIVE_PATTERN.search(e.path)][:5]
        if not sensitive:
            # fall back to checking the first couple of GET endpoints just for header hygiene
            sensitive = [e for e in endpoints if e.method.value == "GET"][:2]

        for ep in sensitive:
            await self._check_burst(ep)

        return self.findings

    async def _check_burst(self, ep: EndpointSpec):
        got_429 = False
        last_resp = None
        has_rate_headers = False

        for i in range(MAX_BURST):
            resp = await self.client.request(
                ep.method.value, ep.path,
                json_body=ep.request_body_sample,
                no_auth=not ep.requires_auth,
            )
            if resp.error:
                break
            last_resp = resp

            if any(resp.header(h) for h in (
                "x-ratelimit-limit", "x-ratelimit-remaining", "ratelimit-limit", "retry-after"
            )):
                has_rate_headers = True

            if resp.status_code == 429:
                got_429 = True
                break  # stop immediately — no reason to keep probing once confirmed

        if last_resp is None:
            return

        if not got_429:
            severity = Severity.HIGH if SENSITIVE_PATTERN.search(ep.path) else Severity.MEDIUM
            self.add_finding(
                endpoint=ep.path, method=ep.method.value,
                owasp_category="API4:2023 Unrestricted Resource Consumption",
                issue="No rate limiting detected on sensitive endpoint",
                severity=severity,
                description=(
                    f"{MAX_BURST} consecutive requests to {ep.method.value} {ep.path} all succeeded "
                    f"without ever receiving an HTTP 429 (Too Many Requests) response."
                ),
                impact=(
                    "Without rate limiting, this endpoint is exposed to credential stuffing, brute-force, "
                    "OTP-guessing, or resource-exhaustion attacks."
                ),
                recommendation=(
                    "Add per-IP and per-account rate limiting (e.g. token-bucket or sliding-window) on this "
                    "route, returning 429 with a Retry-After header once the limit is exceeded."
                ),
                evidence={"requests_sent": min(i + 1, MAX_BURST), "rate_limit_headers_seen": has_rate_headers},
            )
        elif not has_rate_headers:
            self.add_finding(
                endpoint=ep.path, method=ep.method.value,
                owasp_category="API4:2023 Unrestricted Resource Consumption",
                issue="Rate limiting active but no standard headers returned",
                severity=Severity.LOW,
                description="A 429 was eventually returned, but no X-RateLimit-* / Retry-After headers were present to inform well-behaved clients.",
                impact="Legitimate clients (and your own front-end) cannot back off intelligently without guessing.",
                recommendation="Return standard RateLimit-* / Retry-After headers alongside 429 responses (RFC 6585 / draft-ietf-httpapi-ratelimit-headers).",
                evidence={},
            )
