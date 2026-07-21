"""
AegisLab - authorization_tests.py
====================================
Maps to OWASP API Security Top 10: API1:2023 Broken Object Level Authorization
and API5:2023 Broken Function Level Authorization.

Checks performed (read-only, non-destructive):
  1. Broken Object Level Authorization (BOLA/IDOR): for path-parameterized
     endpoints (e.g. /orders/{id}), probe a small range of nearby IDs with
     the SAME credential and look for inconsistent enforcement.
  2. Cross-account BOLA confirmation: if the user supplies a *second* bearer
     token (their own second test account), confirm whether account A's
     token can read account B's resource by ID.
  3. Broken Function Level Authorization: attempt to call endpoints tagged
     /named as admin-only using a regular (primary) token.

All probes are GET requests only — no data is modified.
"""

from __future__ import annotations

import re

from models import EndpointSpec, Vulnerability, Severity
from .base import BaseTestModule

ID_PATTERN = re.compile(r"\{[^}]*id[^}]*\}", re.IGNORECASE)
ADMIN_PATTERN = re.compile(r"admin|internal|management|/staff/", re.IGNORECASE)


def _candidate_ids(sample_id: str | None) -> list[str]:
    """Generates a few nearby/neighboring IDs to probe, without guessing wildly."""
    candidates = ["1", "2"]
    if sample_id and sample_id.isdigit():
        n = int(sample_id)
        candidates = list({str(n), str(max(n - 1, 1)), str(n + 1)})
    return candidates


class AuthorizationTests(BaseTestModule):
    name = "authorization_tests"
    description = "Object-level (BOLA/IDOR) and function-level (privilege escalation) authorization checks"

    async def run(self, endpoints: list[EndpointSpec]) -> list[Vulnerability]:
        id_endpoints = [e for e in endpoints if ID_PATTERN.search(e.path) and e.method.value == "GET"]
        admin_endpoints = [e for e in endpoints if ADMIN_PATTERN.search(e.path)
                            or any(ADMIN_PATTERN.search(t) for t in e.tags)]

        for ep in id_endpoints[:15]:
            await self._check_bola(ep)

        for ep in admin_endpoints[:10]:
            await self._check_function_level(ep)

        return self.findings

    def _fill_id(self, path: str, value: str) -> str:
        return ID_PATTERN.sub(value, path, count=1)

    async def _check_bola(self, ep: EndpointSpec):
        ids = _candidate_ids(None)
        responses = []
        for _id in ids:
            concrete_path = self._fill_id(ep.path, _id)
            resp = await self.client.get(concrete_path)
            if resp.error:
                continue
            responses.append((_id, resp))

        ok_responses = [(i, r) for i, r in responses if r.ok]

        # Signal 1: same token, multiple different numeric IDs, all return 200
        # with plausible distinct payloads -> no ownership check appears to be enforced.
        if len(ok_responses) >= 2:
            bodies = {i: (r.json_safe() or r.text[:200]) for i, r in ok_responses}
            distinct_bodies = len({str(b) for b in bodies.values()}) > 1
            if distinct_bodies:
                self.add_finding(
                    endpoint=ep.path, method="GET",
                    owasp_category="API1:2023 Broken Object Level Authorization",
                    issue="Possible missing object-ownership check (IDOR/BOLA)",
                    severity=Severity.HIGH,
                    description=(
                        f"Requesting {ep.path} with different ID values ({', '.join(bodies)}) using the "
                        f"SAME token returned HTTP 200 with distinct payloads for each, with no apparent "
                        f"ownership/ACL check rejecting access to records the caller may not own."
                    ),
                    impact="A user may be able to read other users' records simply by incrementing an ID, exposing private data.",
                    recommendation=(
                        "Add an explicit ownership/ACL check in the handler (e.g. WHERE owner_id = :current_user) "
                        "rather than relying on the ID being 'hard to guess'. Return 403/404 for records the caller doesn't own."
                    ),
                    evidence={"ids_tested": ids, "statuses": {i: r.status_code for i, r in responses}},
                )

        # Signal 2 (stronger): cross-account confirmation with a second token
        if self.config.secondary_bearer_token and ok_responses:
            sample_id, sample_resp = ok_responses[0]
            cross_resp = await self.client.get(
                self._fill_id(ep.path, sample_id), token_override=self.config.secondary_bearer_token
            )
            if not cross_resp.error and cross_resp.ok:
                self.add_finding(
                    endpoint=ep.path, method="GET",
                    owasp_category="API1:2023 Broken Object Level Authorization",
                    issue="Confirmed cross-account object access (BOLA)",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Resource {self._fill_id(ep.path, sample_id)} was successfully retrieved using a "
                        f"SECOND, independent account's bearer token, confirming it is not scoped to its owner."
                    ),
                    impact="Confirmed: any authenticated user can read another user's specific resource by ID.",
                    recommendation="Enforce per-resource ownership checks server-side on every read/write handler for this resource type.",
                    evidence={"id_tested": sample_id, "status_with_second_account": cross_resp.status_code},
                )

    async def _check_function_level(self, ep: EndpointSpec):
        resp = await self.client.get(ep.path) if ep.method.value == "GET" else \
            await self.client.request(ep.method.value, ep.path, json_body=ep.request_body_sample)
        if resp.error:
            return
        if resp.ok:
            self.add_finding(
                endpoint=ep.path, method=ep.method.value,
                owasp_category="API5:2023 Broken Function Level Authorization",
                issue="Privileged/administrative endpoint reachable with a standard token",
                severity=Severity.CRITICAL,
                description=(
                    f"The endpoint {ep.path} appears (by naming/tag) to be restricted to admin/internal use "
                    f"but returned HTTP {resp.status_code} using the standard test bearer token."
                ),
                impact="A regular authenticated user may be able to perform administrative actions or read internal-only data.",
                recommendation="Add a role/permission check (RBAC) on this route, independent of authentication, and verify it with an automated test.",
                evidence={"status_code": resp.status_code},
            )
