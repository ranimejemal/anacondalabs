"""
AegisLab - mass_assignment_tests.py
======================================
Maps to OWASP API Security Top 10: API6:2023 Unrestricted Access to
Sensitive Business Flows / API3:2023 Broken Object Property Level
Authorization (the successor category to the old "Mass Assignment" entry).

DETECTION ONLY: for each write endpoint with a known request body shape,
sends the original body PLUS one extra, privileged-sounding field that was
NOT part of the original schema (e.g. "role": "admin", "isAdmin": true,
"price": 0). This never sends a body that omits or corrupts the user's
real fields — only adds one extra field at a time — so a false accept
can't itself cause meaningful damage beyond what the field controls.

A finding is only raised when the response POSITIVELY CONFIRMS the field
was accepted — i.e. the API's own response body echoes the injected value
back (the common REST pattern of returning the created/updated resource).
A bare 2xx status alone is not enough evidence (many frameworks accept-then-
silently-strip unknown fields), so we deliberately don't flag on that alone
to avoid noisy false positives.
"""

from __future__ import annotations

from typing import Any

from models import EndpointSpec, Vulnerability, Severity
from .base import BaseTestModule

# field_name -> probe value. Chosen to be unambiguous if reflected: an
# attacker-controlled privilege/financial field with a value nobody's
# legitimate "create user" or "update profile" form would ever send.
PROBE_FIELDS: dict[str, Any] = {
    "role": "admin",
    "isAdmin": True,
    "is_admin": True,
    "admin": True,
    "permissions": ["admin"],
    "price": 0,
    "balance": 999999,
    "credits": 999999,
    "isVerified": True,
    "is_verified": True,
    "premium": True,
    "plan": "enterprise",
}

MAX_ENDPOINTS = 15
MAX_PROBES_PER_ENDPOINT = 4


class MassAssignmentTests(BaseTestModule):
    name = "mass_assignment_tests"
    description = "Detects unrestricted mass assignment on write endpoints (unexpected privileged fields accepted)"

    async def run(self, endpoints: list[EndpointSpec]) -> list[Vulnerability]:
        write_endpoints = [
            e for e in endpoints
            if e.method.value in ("POST", "PUT", "PATCH") and e.request_body_sample
        ][:MAX_ENDPOINTS]

        for ep in write_endpoints:
            await self._probe_endpoint(ep)

        return self.findings

    async def _probe_endpoint(self, ep: EndpointSpec):
        base_body = dict(ep.request_body_sample or {})
        existing_keys = {k.lower() for k in base_body.keys()}

        # Only probe fields that AREN'T already part of the endpoint's own
        # schema — the whole point is testing fields the client shouldn't
        # know are settable at all.
        candidate_fields = [
            (field, value) for field, value in PROBE_FIELDS.items()
            if field.lower() not in existing_keys
        ][:MAX_PROBES_PER_ENDPOINT]

        for field, probe_value in candidate_fields:
            probe_body = dict(base_body)
            probe_body[field] = probe_value

            resp = await self.client.request(ep.method.value, ep.path, json_body=probe_body)
            if resp.error or not resp.ok:
                continue  # rejected or unreachable — not a finding either way

            data = resp.json_safe()
            if not isinstance(data, dict):
                continue

            reflected = self._find_reflected_value(data, field, probe_value)
            if reflected:
                self.add_finding(
                    endpoint=ep.path, method=ep.method.value,
                    owasp_category="API3:2023 Broken Object Property Level Authorization",
                    issue=f"Mass assignment: unexpected field '{field}' accepted and reflected",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Sending an undocumented '{field}' field (value: {probe_value!r}) alongside the "
                        f"normal request body was accepted (HTTP {resp.status_code}), and the response "
                        f"echoed it back — meaning the server stored or applied a field the client should "
                        f"never have been able to set directly."
                    ),
                    impact=(
                        "A real attacker could set this field to escalate privileges (role/isAdmin), "
                        "manipulate pricing or balances, or flip verification/premium flags — entirely "
                        "through a normal-looking write request, without any other vulnerability needed."
                    ),
                    recommendation=(
                        "Use an explicit allowlist (DTO / whitelist pattern) for writable fields instead of "
                        "binding the raw request body to your model. Server-controlled fields (role, price, "
                        "verified status, etc.) must never be settable from client input at all."
                    ),
                    evidence={"field": field, "sent_value": probe_value, "status": resp.status_code},
                )
                # One confirmed finding per endpoint is enough signal; move on
                # rather than piling on near-duplicate findings for the same root cause.
                return

    @staticmethod
    def _find_reflected_value(data: dict, field: str, probe_value: Any) -> bool:
        """Checks the top level and one level of nesting (a common
        {"data": {...}} or {"user": {...}} wrapper) for the field being
        echoed back with the exact probed value."""
        if field in data and data[field] == probe_value:
            return True
        for v in data.values():
            if isinstance(v, dict) and field in v and v[field] == probe_value:
                return True
        return False
