"""
AegisLab - ssrf_tests.py
==========================
Maps to OWASP API Security Top 10: API7:2023 Server Side Request Forgery.

"Basic version" as scoped for v1 — two independent checks, neither requiring
infrastructure AegisLab doesn't already have:

  1. Cloud metadata probe (self-contained, no external service needed):
     injects the well-known AWS/GCP/Azure instance-metadata address into
     URL/callback-shaped parameters and body fields, then checks the
     response for metadata-service signatures (instance IDs, IAM role
     names, etc.) being reflected back. This alone is a strong, safe,
     self-contained SSRF signal — if a server fetches attacker-supplied
     URLs server-side and metadata content comes back, that's confirmed,
     not a heuristic.

  2. Optional out-of-band callback check: IF the user supplies their own
     `ssrf_callback_url` (from a service like webhook.site or interact.sh
     that they control) in ScanConfig, AegisLab also sends that URL into
     the same fields. AegisLab can't see whether the target's server
     actually called back out-of-band — it just flags this as INFO with
     instructions to check the callback service's own dashboard, since
     confirming that requires the user's own out-of-band service, not
     something this scanner can verify itself.

Both checks are single, harmless GET/read requests to attacker-controlled
or well-known-benign addresses — never anything that could reach a real
internal system beyond the well-known cloud metadata IP ranges, which by
design only respond to requests actually originating from inside that
cloud environment (so this probe is inert against any target that isn't
itself vulnerable).
"""

from __future__ import annotations

from models import EndpointSpec, Vulnerability, Severity
from .base import BaseTestModule

# Well-known cloud instance-metadata endpoints. 169.254.169.254 is the
# link-local address used by AWS, Azure, and (with a header) GCP — it's
# only reachable from inside that specific cloud instance, so probing it
# from AegisLab's own process is inert; the only way we'd see metadata
# content in the response is if the TARGET server fetched it server-side.
METADATA_PROBE_URL = "http://169.254.169.254/latest/meta-data/"
METADATA_SIGNATURES = [
    "ami-id", "instance-id", "iam/security-credentials", "instance-action",
    "local-ipv4", "public-keys", "security-credentials", "hostname",
]

# Parameter/field names likely to be passed straight to a server-side fetch.
SSRF_PRONE_NAME_HINTS = [
    "url", "uri", "link", "callback", "webhook", "redirect", "target",
    "endpoint", "src", "source", "image_url", "avatar", "file_url", "feed",
]

MAX_ENDPOINTS = 15


class SsrfTests(BaseTestModule):
    name = "ssrf_tests"
    description = "Basic SSRF detection: cloud metadata probe on URL-shaped parameters, plus optional out-of-band callback check"

    async def run(self, endpoints: list[EndpointSpec]) -> list[Vulnerability]:
        candidates = self._find_ssrf_prone_endpoints(endpoints)[:MAX_ENDPOINTS]
        for ep, param_kind, field_name in candidates:
            await self._probe(ep, param_kind, field_name)
        return self.findings

    @staticmethod
    def _find_ssrf_prone_endpoints(endpoints: list[EndpointSpec]):
        """Yields (endpoint, 'query'|'body', field_name) for every
        parameter/field whose name suggests it's used for a server-side fetch."""
        out = []
        for ep in endpoints:
            for p in ep.params:
                if any(h in p.lower() for h in SSRF_PRONE_NAME_HINTS):
                    out.append((ep, "query", p))
            if ep.request_body_sample:
                for k in ep.request_body_sample.keys():
                    if any(h in k.lower() for h in SSRF_PRONE_NAME_HINTS):
                        out.append((ep, "body", k))
        return out

    async def _probe(self, ep: EndpointSpec, param_kind: str, field_name: str):
        # --- 1. Cloud metadata probe (self-contained, always runs) ---
        resp = await self._send(ep, param_kind, field_name, METADATA_PROBE_URL)
        if resp and not resp.error:
            found_sigs = [s for s in METADATA_SIGNATURES if s in resp.text.lower()]
            if found_sigs:
                self.add_finding(
                    endpoint=ep.path, method=ep.method.value,
                    owasp_category="API7:2023 Server Side Request Forgery",
                    issue=f"Server-side request forgery via '{field_name}' — cloud metadata reachable",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Pointing the '{field_name}' {param_kind} parameter at the cloud instance metadata "
                        f"address (169.254.169.254) caused the response to include metadata-service content "
                        f"({found_sigs[0]}) — the server fetched an attacker-supplied URL itself."
                    ),
                    impact=(
                        "If this API runs on AWS/GCP/Azure, an attacker can use this to steal the instance's "
                        "IAM credentials from the metadata service, potentially compromising far more than "
                        "just this API (full cloud account access depending on the role's permissions)."
                    ),
                    recommendation=(
                        "Never fetch a raw user-supplied URL server-side. Use an allowlist of permitted "
                        "hosts/schemes, resolve and reject requests to link-local/private IP ranges "
                        "(169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8) before "
                        "connecting, and disable HTTP redirects when following user-supplied URLs."
                    ),
                    evidence={"field": field_name, "param_kind": param_kind, "signature_found": found_sigs[0]},
                )
                return  # confirmed — no need for the weaker callback check too

        # --- 2. Optional out-of-band callback check ---
        callback_url = getattr(self.config, "ssrf_callback_url", None)
        if callback_url:
            cb_resp = await self._send(ep, param_kind, field_name, callback_url)
            if cb_resp and not cb_resp.error and cb_resp.ok:
                self.add_finding(
                    endpoint=ep.path, method=ep.method.value,
                    owasp_category="API7:2023 Server Side Request Forgery",
                    issue=f"Possible SSRF via '{field_name}' — callback URL accepted, verify out-of-band",
                    severity=Severity.INFO,
                    description=(
                        f"The '{field_name}' {param_kind} parameter accepted your callback URL "
                        f"(HTTP {cb_resp.status_code}). AegisLab cannot itself see whether the target's "
                        f"server actually made an outbound request to it — check your callback service's "
                        f"own dashboard/logs for a hit from this endpoint to confirm."
                    ),
                    impact="If the server did fetch the callback URL, it confirms server-side outbound requests are attacker-controllable, the same underlying flaw as the metadata check above.",
                    recommendation="Same as above: allowlist permitted destination hosts before making any server-side request built from user input.",
                    evidence={"field": field_name, "param_kind": param_kind, "callback_url": callback_url},
                )

    async def _send(self, ep: EndpointSpec, param_kind: str, field_name: str, value: str):
        if param_kind == "query":
            return await self.client.get(ep.path, params={field_name: value})
        base_body = dict(ep.request_body_sample or {})
        base_body[field_name] = value
        return await self.client.request(ep.method.value, ep.path, json_body=base_body)
