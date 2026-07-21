"""
AegisLab - Test Module Base
=============================
Shared base class for every security test module. Provides the standard
`run(endpoints, client) -> list[Vulnerability]` contract and small helpers
for building consistent findings.

SAFETY NOTE: every module in this package is a *detection* tool, not an
exploitation tool. Modules send small, well-known, non-destructive probe
values (the same canonical test strings published in the OWASP Testing
Guide) and look for evidence of a problem in the response. They never:
  - attempt to actually exfiltrate data at scale
  - run real destructive operations (DROP/DELETE-style payloads)
  - attempt to gain real unauthorized access beyond confirming a response
    code / shape that indicates a flaw exists
All scans require the user to explicitly confirm they are authorized to
test the target (`ScanConfig.confirm_authorized`), enforced in scanner.py.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from models import EndpointSpec, Vulnerability, Severity
from api_client import SafeApiClient, ApiResponse


class BaseTestModule(ABC):
    name: str = "base"
    description: str = ""

    def __init__(self, client: SafeApiClient, config):
        self.client = client
        self.config = config
        self.findings: list[Vulnerability] = []

    @abstractmethod
    async def run(self, endpoints: list[EndpointSpec]) -> list[Vulnerability]:
        ...

    def add_finding(
        self,
        endpoint: str,
        method: str,
        owasp_category: str,
        issue: str,
        severity: Severity,
        description: str,
        impact: str,
        recommendation: str,
        evidence: Optional[dict] = None,
    ) -> Vulnerability:
        finding = Vulnerability(
            endpoint=endpoint,
            method=method,
            test_module=self.name,
            owasp_category=owasp_category,
            issue=issue,
            severity=severity,
            description=description,
            impact=impact,
            recommendation=recommendation,
            evidence=evidence or {},
        )
        self.findings.append(finding)
        return finding

    @staticmethod
    def looks_like_error_leak(text: str) -> list[str]:
        """Detects common stack-trace / verbose error signatures in a response body."""
        signatures = [
            "Traceback (most recent call last)", "at Object.<anonymous>",
            "System.Exception", "org.springframework", "Microsoft.Data.SqlClient",
            "PG::", "SQLSTATE", "ORA-0", "django.db.utils", "sequelize",
            "prisma.io", "stacktrace", "stack_trace", "<!-- Stack Trace -->",
        ]
        return [s for s in signatures if s.lower() in text.lower()]

    @staticmethod
    def looks_like_sensitive_field(key: str) -> bool:
        sensitive_markers = [
            "password", "passwd", "secret", "token", "api_key", "apikey",
            "ssn", "credit_card", "creditcard", "cvv", "private_key",
            "access_token", "refresh_token", "session", "auth_hash",
        ]
        key_lower = key.lower()
        return any(m in key_lower for m in sensitive_markers)
