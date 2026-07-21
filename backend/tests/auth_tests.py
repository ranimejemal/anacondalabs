"""
AegisLab - auth_tests.py
==========================
Maps to OWASP API Security Top 10: API2:2023 Broken Authentication.

Checks performed (all read-only / non-destructive):
  1. Endpoints marked as requiring auth actually reject unauthenticated requests
  2. Endpoints reject obviously invalid / malformed bearer tokens
  3. JWT structural inspection (alg=none, missing expiry) WITHOUT attempting
     to forge or crack any signature
  4. Verbose authentication error messages that leak account existence
     (e.g. "user not found" vs "wrong password")
  5. Auth errors that leak stack traces / internal framework details
"""

from __future__ import annotations

import base64
import json
import re

from models import EndpointSpec, Vulnerability, Severity
from .base import BaseTestModule

JUNK_TOKENS = [
    "this.is.not.a.valid.jwt",
    "Bearer",
    "null",
    "undefined",
    "" .join(["A"] * 20),
]


def _try_decode_jwt(token: str) -> dict | None:
    """Best-effort, non-verifying decode of a JWT header+payload (inspection only)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        def pad(b: str) -> str:
            return b + "=" * (-len(b) % 4)
        header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
        return {"header": header, "payload": payload}
    except Exception:
        return None


class AuthTests(BaseTestModule):
    name = "auth_tests"
    description = "Authentication enforcement, token handling, and error-message hygiene"

    async def run(self, endpoints: list[EndpointSpec]) -> list[Vulnerability]:
        protected = [e for e in endpoints if e.requires_auth]

        for ep in protected[:25]:  # cap to keep scans fast & polite to the target
            await self._check_missing_auth_rejection(ep)
            await self._check_invalid_token_rejection(ep)

        if self.config.bearer_token:
            self._check_jwt_structure(self.config.bearer_token)

        await self._check_verbose_login_errors(endpoints)

        return self.findings

    async def _check_missing_auth_rejection(self, ep: EndpointSpec):
        resp = await self.client.request(ep.method.value, ep.path, no_auth=True,
                                          json_body=ep.request_body_sample)
        if resp.error:
            return
        if resp.ok:
            self.add_finding(
                endpoint=ep.path, method=ep.method.value,
                owasp_category="API2:2023 Broken Authentication",
                issue="Protected endpoint accessible without authentication",
                severity=Severity.CRITICAL,
                description=(
                    f"The endpoint {ep.method.value} {ep.path} is expected to require "
                    f"authentication (per the imported spec) but returned HTTP "
                    f"{resp.status_code} with no Authorization header supplied."
                ),
                impact="Unauthenticated users may read or modify data that should be restricted to logged-in users.",
                recommendation=(
                    "Enforce an authentication guard/middleware on this route and verify it runs "
                    "before any business logic. Add an automated test that asserts 401 on missing credentials."
                ),
                evidence={"status_code": resp.status_code, "request": "no Authorization header"},
            )

    async def _check_invalid_token_rejection(self, ep: EndpointSpec):
        for junk in JUNK_TOKENS[:2]:  # sample a couple, not the whole list, per endpoint
            resp = await self.client.request(ep.method.value, ep.path, token_override=junk,
                                              json_body=ep.request_body_sample)
            if resp.error:
                continue
            if resp.ok:
                self.add_finding(
                    endpoint=ep.path, method=ep.method.value,
                    owasp_category="API2:2023 Broken Authentication",
                    issue="Endpoint accepts a malformed/invalid bearer token",
                    severity=Severity.HIGH,
                    description=(
                        f"Sending a syntactically invalid bearer token to {ep.path} returned "
                        f"HTTP {resp.status_code} instead of a 401 Unauthorized."
                    ),
                    impact="Indicates token validation may be missing, fail-open, or only checked on some code paths.",
                    recommendation="Verify JWT/opaque token validation runs on every request and fails closed on any parse/verify error.",
                    evidence={"status_code": resp.status_code, "token_sample": junk[:20]},
                )
                return  # one finding per endpoint is enough signal

    def _check_jwt_structure(self, token: str):
        decoded = _try_decode_jwt(token)
        if not decoded:
            return
        header, payload = decoded["header"], decoded["payload"]

        if str(header.get("alg", "")).lower() == "none":
            self.add_finding(
                endpoint="(provided bearer token)", method="N/A",
                owasp_category="API2:2023 Broken Authentication",
                issue="JWT uses 'alg: none'",
                severity=Severity.CRITICAL,
                description="The bearer token supplied for testing declares alg=none in its header, meaning the signature is not verified by spec.",
                impact="If the backend also accepts alg=none, an attacker can forge arbitrary tokens with no signature at all.",
                recommendation="Reject tokens with alg=none server-side and pin the expected algorithm (e.g. RS256) explicitly when verifying.",
                evidence={"header": header},
            )

        if "exp" not in payload:
            self.add_finding(
                endpoint="(provided bearer token)", method="N/A",
                owasp_category="API2:2023 Broken Authentication",
                issue="JWT has no expiry (exp) claim",
                severity=Severity.MEDIUM,
                description="The decoded JWT payload does not contain an 'exp' claim.",
                impact="Tokens without an expiry remain valid indefinitely if leaked, increasing the blast radius of any token compromise.",
                recommendation="Issue tokens with a short-lived 'exp' claim and use refresh tokens for longer sessions.",
                evidence={"payload_keys": list(payload.keys())},
            )

    async def _check_verbose_login_errors(self, endpoints: list[EndpointSpec]):
        login_eps = [e for e in endpoints if re.search(r"login|signin|authenticate", e.path, re.I)
                     and e.method.value == "POST"]
        for ep in login_eps[:3]:
            resp_unknown_user = await self.client.post(
                ep.path, no_auth=True,
                json_body={"email": "aegislab_nonexistent_user_9f3a@example.com", "password": "WrongPass123!"}
            )
            resp_bad_pass = await self.client.post(
                ep.path, no_auth=True,
                json_body={"email": "admin@example.com", "password": "AegisLabWrongPass!1"}
            )
            if resp_unknown_user.error or resp_bad_pass.error:
                continue

            t1, t2 = resp_unknown_user.text.lower(), resp_bad_pass.text.lower()
            distinguishing = ("not found" in t1 and "not found" not in t2) or \
                              ("no user" in t1 and "no user" not in t2) or \
                              (resp_unknown_user.status_code != resp_bad_pass.status_code)

            if distinguishing:
                self.add_finding(
                    endpoint=ep.path, method="POST",
                    owasp_category="API2:2023 Broken Authentication",
                    issue="Login error messages leak account existence",
                    severity=Severity.MEDIUM,
                    description=(
                        "The login endpoint returns distinguishable responses for "
                        "'unknown account' vs 'wrong password', allowing account enumeration."
                    ),
                    impact="Attackers can build a list of valid/registered email addresses for targeted phishing or credential stuffing.",
                    recommendation="Return an identical generic message (e.g. 'Invalid email or password') and identical status code/timing for both cases.",
                    evidence={
                        "status_unknown_user": resp_unknown_user.status_code,
                        "status_wrong_password": resp_bad_pass.status_code,
                    },
                )

            for resp in (resp_unknown_user, resp_bad_pass):
                leaks = self.looks_like_error_leak(resp.text)
                if leaks:
                    self.add_finding(
                        endpoint=ep.path, method="POST",
                        owasp_category="API8:2023 Security Misconfiguration",
                        issue="Authentication error response leaks internal implementation details",
                        severity=Severity.MEDIUM,
                        description=f"The login endpoint's error response contains framework/stack trace markers: {', '.join(leaks)}.",
                        impact="Internal stack traces reveal framework versions, file paths, and ORM details useful for further attack planning.",
                        recommendation="Disable verbose/debug error output in production and return sanitized, generic error bodies.",
                        evidence={"signatures_found": leaks},
                    )
                    break
