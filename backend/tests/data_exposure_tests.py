"""
AegisLab - data_exposure_tests.py
====================================
Maps to OWASP API Security Top 10: API3:2023 Broken Object Property Level
Authorization (excessive data exposure) and API8:2023 Security Misconfiguration.

Checks performed (all read-only):
  1. Sensitive field exposure: scans JSON response bodies for keys that
     look like secrets/credentials/PII that should never be serialized
     (password hashes, internal tokens, etc.)
  2. Excessive data exposure: flags responses that include internal/
     implementation fields (e.g. __v, internal_notes, is_deleted, _id
     alongside a public id) that look like a raw DB row dump rather
     than a deliberately-shaped DTO.
  3. CORS misconfiguration: wildcard origin combined with credentials
     allowed (the dangerous combination), or unrestricted wildcard origin
     on an authenticated endpoint.
  4. Verbose server fingerprinting headers (Server, X-Powered-By) leaking
     exact framework/version.
"""

from __future__ import annotations

from models import EndpointSpec, Vulnerability, Severity
from .base import BaseTestModule

INTERNAL_FIELD_MARKERS = [
    "__v", "internal_notes", "is_deleted", "deleted_at", "raw_password",
    "password_hash", "hashed_password", "salt", "_internal", "debug",
]


class DataExposureTests(BaseTestModule):
    name = "data_exposure_tests"
    description = "Sensitive field leakage, excessive data exposure, CORS, and server fingerprinting checks"

    def __init__(self, client, config):
        super().__init__(client, config)
        self._cors_checked = False

    async def run(self, endpoints: list[EndpointSpec]) -> list[Vulnerability]:
        get_endpoints = [e for e in endpoints if e.method.value == "GET"][:20]

        for ep in get_endpoints:
            resp = await self.client.get(ep.path)
            if resp.error or not resp.ok:
                continue

            self._check_sensitive_fields(ep, resp)
            self._check_excessive_exposure(ep, resp)
            self._check_fingerprint_headers(ep, resp)
            if not self._cors_checked:
                self._check_cors(ep, resp)
                self._cors_checked = True

        return self.findings

    def _walk_keys(self, obj, path="") -> list[tuple[str, str]]:
        found = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                found.append((k, f"{path}.{k}" if path else k))
                found.extend(self._walk_keys(v, f"{path}.{k}" if path else k))
        elif isinstance(obj, list):
            for i, item in enumerate(obj[:5]):  # cap traversal of large arrays
                found.extend(self._walk_keys(item, f"{path}[{i}]"))
        return found

    def _check_sensitive_fields(self, ep: EndpointSpec, resp):
        data = resp.json_safe()
        if data is None:
            return
        hits = [(k, p) for k, p in self._walk_keys(data) if self.looks_like_sensitive_field(k)]
        if hits:
            unique_keys = sorted({k for k, _ in hits})
            self.add_finding(
                endpoint=ep.path, method="GET",
                owasp_category="API3:2023 Broken Object Property Level Authorization",
                issue="Response body includes sensitive/credential-like fields",
                severity=Severity.HIGH,
                description=f"The response from {ep.path} includes one or more fields that look like secrets or credentials: {', '.join(unique_keys)}.",
                impact="Sensitive fields such as password hashes or tokens should never be serialized to API clients; exposure can lead to account takeover if leaked further (logs, browser devtools, caches).",
                recommendation="Use an explicit response DTO/serializer that allow-lists exposed fields, rather than returning the raw database model.",
                evidence={"fields_found": unique_keys},
            )

    def _check_excessive_exposure(self, ep: EndpointSpec, resp):
        data = resp.json_safe()
        if data is None:
            return
        keys = {k for k, _ in self._walk_keys(data)}
        hits = sorted(keys & set(INTERNAL_FIELD_MARKERS))
        if hits:
            self.add_finding(
                endpoint=ep.path, method="GET",
                owasp_category="API3:2023 Broken Object Property Level Authorization",
                issue="Response appears to expose internal/implementation fields (excessive data exposure)",
                severity=Severity.MEDIUM,
                description=f"The response includes internal-looking fields not typically meant for API consumers: {', '.join(hits)}.",
                impact="Returning raw database rows leaks schema/implementation details and may include fields with no intended external use, increasing attack surface for object-property-level attacks.",
                recommendation="Map database models to dedicated response DTOs and explicitly select only the fields the API contract requires.",
                evidence={"fields_found": hits},
            )

    def _check_fingerprint_headers(self, ep: EndpointSpec, resp):
        server = resp.header("server")
        powered_by = resp.header("x-powered-by")
        if powered_by:
            self.add_finding(
                endpoint=ep.path, method="GET",
                owasp_category="API8:2023 Security Misconfiguration",
                issue="X-Powered-By header reveals backend framework",
                severity=Severity.LOW,
                description=f"The response includes an X-Powered-By header value of '{powered_by}'.",
                impact="Knowing the exact framework/version helps attackers select known exploits faster.",
                recommendation="Disable the X-Powered-By header (e.g. app.disable('x-powered-by') in Express, or equivalent middleware config).",
                evidence={"header_value": powered_by},
            )
        if server and any(v in server.lower() for v in ("/", "version")):
            self.add_finding(
                endpoint=ep.path, method="GET",
                owasp_category="API8:2023 Security Misconfiguration",
                issue="Server header reveals detailed version information",
                severity=Severity.LOW,
                description=f"The Server header returns a detailed value: '{server}'.",
                impact="Version-specific fingerprinting narrows down which CVEs may apply to this deployment.",
                recommendation="Configure the web/app server or reverse proxy to return a generic Server header (or omit it).",
                evidence={"header_value": server},
            )

    def _check_cors(self, ep: EndpointSpec, resp):
        acao = resp.header("access-control-allow-origin")
        acac = resp.header("access-control-allow-credentials")
        if acao == "*" and str(acac).lower() == "true":
            self.add_finding(
                endpoint=ep.path, method="GET",
                owasp_category="API8:2023 Security Misconfiguration",
                issue="Dangerous CORS configuration: wildcard origin with credentials allowed",
                severity=Severity.CRITICAL,
                description="The API returns Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.",
                impact="Most browsers will reject this combination, but where supported it lets ANY website read authenticated responses on behalf of a logged-in victim, leading to full account compromise via CSRF-style requests.",
                recommendation="Echo back a specific allow-listed origin (never '*') whenever Allow-Credentials is true.",
                evidence={"access_control_allow_origin": acao, "access_control_allow_credentials": acac},
            )
        elif acao == "*":
            self.add_finding(
                endpoint=ep.path, method="GET",
                owasp_category="API8:2023 Security Misconfiguration",
                issue="CORS allows requests from any origin",
                severity=Severity.LOW,
                description="The API returns Access-Control-Allow-Origin: * for this endpoint.",
                impact="Any website can call this endpoint from a user's browser; acceptable for fully public, non-sensitive data only.",
                recommendation="Confirm this endpoint truly serves only public, non-sensitive data; otherwise restrict to specific origins.",
                evidence={"access_control_allow_origin": acao},
            )
