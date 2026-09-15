"""
AegisLab - Data Models
=======================
Shared data structures used across the security engine: scan configuration,
discovered endpoints, vulnerability findings, and scan results.
"""

from __future__ import annotations

import uuid
import time
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class EndpointSpec(BaseModel):
    """A single API endpoint discovered from OpenAPI/Swagger or entered manually."""
    path: str
    method: HttpMethod = HttpMethod.GET
    requires_auth: bool = True
    description: str = ""
    params: list[str] = Field(default_factory=list)
    request_body_sample: Optional[dict] = None
    tags: list[str] = Field(default_factory=list)

    @field_validator("path")
    @classmethod
    def normalize_path(cls, v: str) -> str:
        if not v.startswith("/"):
            v = "/" + v
        return v


class ScanConfig(BaseModel):
    """User-supplied configuration for a scan. Mirrors the dashboard form."""
    base_url: str
    bearer_token: Optional[str] = None
    secondary_bearer_token: Optional[str] = None  # used for authorization/IDOR tests (a 2nd user)
    endpoints: list[EndpointSpec] = Field(default_factory=list)
    modules_enabled: list[str] = Field(default_factory=lambda: [
        "auth_tests",
        "authorization_tests",
        "injection_tests",
        "rate_limit_tests",
        "data_exposure_tests",
        "transport_security_tests",
        "mass_assignment_tests",
        "ssrf_tests",
        "inventory_tests",
    ])
    requests_per_second: float = 5.0  # throttle to keep tests safe on the target
    confirm_authorized: bool = False  # MUST be true to run — explicit consent gate
    # Optional: a URL from a callback/canary service you control (e.g.
    # webhook.site, interact.sh) for the fuller out-of-band SSRF check.
    # Without it, ssrf_tests still runs its self-contained cloud-metadata
    # probe, just without the out-of-band confirmation leg.
    ssrf_callback_url: Optional[str] = None

    @field_validator("base_url")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")


class Vulnerability(BaseModel):
    """A single finding, matching the AegisLab report schema."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    endpoint: str
    method: str = "GET"
    test_module: str
    owasp_category: str
    issue: str
    severity: Severity
    description: str
    impact: str
    recommendation: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    detected_at: float = Field(default_factory=time.time)

    def to_report_dict(self) -> dict:
        """Matches the exact output format requested in the spec."""
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "issue": self.issue,
            "severity": self.severity.value,
            "description": self.description,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "owasp_category": self.owasp_category,
            "test_module": self.test_module,
            "evidence": self.evidence,
        }


class ScanProgressEvent(BaseModel):
    scan_id: str
    module: str
    status: str  # "started" | "running" | "completed" | "error"
    message: str = ""
    percent: int = 0
    findings_so_far: int = 0


class ScanResult(BaseModel):
    scan_id: str
    base_url: str
    started_at: float
    finished_at: Optional[float] = None
    status: str = "running"  # running | completed | failed
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    security_score: Optional[int] = None
    score_breakdown: dict = Field(default_factory=dict)
    endpoints_tested: int = 0
    modules_run: list[str] = Field(default_factory=list)
