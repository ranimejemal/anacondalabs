"""
AegisLab - inventory_tests.py
================================
Maps to OWASP API Security Top 10: API9:2023 Improper Inventory Management.

The README previously scoped this category out as "not observable from a
single scan" — true for a *complete* inventory audit (that needs asset
records AegisLab doesn't have access to), but two concrete, single-scan-
observable signals of the same underlying problem ARE within reach:

  1. Shadow / zombie API versions: if the imported spec declares
     `/api/v2/users`, is the sibling `/api/v1/users` (or `/v3/...`) still
     live? A version nobody remembers to decommission keeps running with
     whatever security posture it had the day it was superseded — patches
     applied to the current version don't retroactively apply to it.

  2. Exposed documentation / introspection endpoints that aren't part of
     the declared inventory at all: framework-standard paths like
     `/swagger.json`, `/actuator/env`, or a reachable `/graphql` with
     introspection left on. These are commonly left wired up by default
     and forgotten about in production, handing out the full endpoint map
     (or, for actuator's env/beans, live config) to anyone who asks.

Both checks are read-only GET/introspection-query requests to well-known or
declared-adjacent paths — nothing destructive, and nothing outside the
target host itself. A finding only fires on an empirically live response
(not a 404/405), so this stays "confirmed", not speculative, matching the
rest of the engine's philosophy (see base.py).
"""

from __future__ import annotations

import re

from models import EndpointSpec, Vulnerability, Severity
from .base import BaseTestModule

VERSION_RE = re.compile(r"(/v)(\d+)(/|$)", re.IGNORECASE)

# How far from the declared version number to probe (v2 declared -> try v1,
# v3, v4 with span=2; never below v1).
NEARBY_VERSION_SPAN = 2
MAX_VERSION_PROBES = 12

GRAPHQL_PATHS = {"/graphql", "/graphiql"}

# Framework-standard documentation/introspection/management paths that, if
# reachable and not part of the declared inventory, mean the deployed
# surface is bigger than whatever the team thinks they're running.
DISCOVERY_PROBE_PATHS = [
    "/swagger.json", "/swagger-ui.html", "/swagger-ui/index.html",
    "/v2/api-docs", "/v3/api-docs", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/redoc",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    *GRAPHQL_PATHS,
]

# Endpoints whose exposure is a real config-leak risk, not just "docs are
# reachable" — escalated above the LOW baseline.
SENSITIVE_DISCOVERY_PATHS = {"/actuator/env", "/actuator/beans"}
# Endpoints so routinely public-by-design that reachability alone barely
# counts as a finding — still reported, but as INFO.
BENIGN_DISCOVERY_PATHS = {"/actuator", "/actuator/health"}

GRAPHQL_INTROSPECTION_QUERY = {"query": "{__schema{types{name}}}"}


class InventoryTests(BaseTestModule):
    name = "inventory_tests"
    description = (
        "Improper inventory management: undocumented/zombie API versions and "
        "exposed documentation/introspection endpoints not covered by the imported spec"
    )

    async def run(self, endpoints: list[EndpointSpec]) -> list[Vulnerability]:
        declared = {ep.path for ep in endpoints}
        await self._probe_shadow_versions(endpoints, declared)
        await self._probe_discovery_paths(declared)
        return self.findings

    # ---- 1. Shadow / zombie API versions --------------------------------

    async def _probe_shadow_versions(self, endpoints: list[EndpointSpec], declared: set[str]):
        candidates: dict[str, tuple[EndpointSpec, int]] = {}
        for ep in endpoints:
            m = VERSION_RE.search(ep.path)
            if not m:
                continue
            current = int(m.group(2))
            for v in self._nearby_versions(current):
                swapped = VERSION_RE.sub(f"\\g<1>{v}\\3", ep.path, count=1)
                if swapped == ep.path or swapped in declared or swapped in candidates:
                    continue
                candidates[swapped] = (ep, v)
                if len(candidates) >= MAX_VERSION_PROBES:
                    break
            if len(candidates) >= MAX_VERSION_PROBES:
                break

        for swapped_path, (source_ep, probed_version) in candidates.items():
            resp = await self.client.get(swapped_path)
            if not resp or resp.error or resp.status_code in (404, 405):
                continue
            source_version = VERSION_RE.search(source_ep.path).group(2)
            self.add_finding(
                endpoint=swapped_path, method="GET",
                owasp_category="API9:2023 Improper Inventory Management",
                issue=f"Undocumented API version reachable: {swapped_path}",
                severity=Severity.MEDIUM,
                description=(
                    f"'{source_ep.path}' is declared as v{source_version} in the imported spec, but the "
                    f"sibling path '{swapped_path}' (v{probed_version}) also responds (HTTP "
                    f"{resp.status_code}) and isn't part of the declared inventory."
                ),
                impact=(
                    "A live but undocumented API version is a common source of unpatched vulnerabilities: "
                    "security fixes applied to the current version don't automatically reach an older version "
                    "nobody remembered to decommission, and it won't be covered by monitoring or scans that "
                    "only target the documented surface."
                ),
                recommendation=(
                    "Either fully decommission old API versions (return 410 Gone, not a working response) or, "
                    "if the version must stay live, add it to your OpenAPI inventory and apply the same "
                    "security patches and monitoring as the current version."
                ),
                evidence={
                    "status_code": resp.status_code,
                    "source_endpoint": source_ep.path,
                    "probed_path": swapped_path,
                },
            )

    @staticmethod
    def _nearby_versions(current: int) -> list[int]:
        lo = max(1, current - NEARBY_VERSION_SPAN)
        hi = current + NEARBY_VERSION_SPAN
        return [v for v in range(lo, hi + 1) if v != current]

    # ---- 2. Exposed documentation / introspection endpoints -------------

    async def _probe_discovery_paths(self, declared: set[str]):
        for path in DISCOVERY_PROBE_PATHS:
            if path in declared:
                continue  # already part of the known, intentional inventory
            if path in GRAPHQL_PATHS:
                await self._check_graphql_introspection(path)
                continue

            resp = await self.client.get(path, no_auth=True)
            if not resp or resp.error or not resp.ok:
                continue

            if path in SENSITIVE_DISCOVERY_PATHS:
                severity = Severity.HIGH
            elif path in BENIGN_DISCOVERY_PATHS:
                severity = Severity.INFO
            else:
                severity = Severity.LOW

            self.add_finding(
                endpoint=path, method="GET",
                owasp_category="API9:2023 Improper Inventory Management",
                issue=f"Undocumented discovery/introspection endpoint exposed: {path}",
                severity=severity,
                description=(
                    f"'{path}' responded HTTP {resp.status_code} to an unauthenticated request, and isn't part "
                    f"of the endpoints imported into this scan — so it isn't in the tracked inventory either."
                ),
                impact=(
                    "Exposed API documentation or framework introspection endpoints hand an attacker your full "
                    "endpoint map (and, for /actuator/env or /actuator/beans specifically, live configuration "
                    "and environment values) without needing to guess anything."
                ),
                recommendation=(
                    "Require authentication for documentation/introspection endpoints in non-development "
                    "environments, or disable them entirely in production builds, then track whichever you "
                    "keep in your OpenAPI inventory."
                ),
                evidence={"status_code": resp.status_code, "path": path},
            )

    async def _check_graphql_introspection(self, path: str):
        resp = await self.client.request("POST", path, json_body=GRAPHQL_INTROSPECTION_QUERY, no_auth=True)
        if not resp or resp.error or not resp.ok:
            return
        body = resp.json_safe()
        types = None
        if isinstance(body, dict):
            types = ((body.get("data") or {}).get("__schema") or {}).get("types")
        if not types:
            return
        self.add_finding(
            endpoint=path, method="POST",
            owasp_category="API9:2023 Improper Inventory Management",
            issue=f"GraphQL introspection enabled on undocumented endpoint: {path}",
            severity=Severity.HIGH,
            description=(
                f"'{path}' is reachable unauthenticated and accepts a standard __schema introspection query, "
                f"returning {len(types)} type(s) — the entire GraphQL schema (every query, mutation and field) "
                "is enumerable by anyone, and this endpoint isn't part of the scan's declared inventory."
            ),
            impact=(
                "A fully enumerable schema hands an attacker a complete map of every operation the API "
                "supports, including internal/admin mutations that were never meant to be discoverable."
            ),
            recommendation=(
                "Disable introspection in production (every major GraphQL server has a flag for this), and "
                "require authentication for the GraphQL endpoint itself if it isn't meant to be public."
            ),
            evidence={"status_code": resp.status_code, "type_count": len(types)},
        )
