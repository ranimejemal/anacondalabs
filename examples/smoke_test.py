"""Smoke test: runs the real AegisLab scanner against the mock vulnerable API
and writes example JSON/PDF reports into examples/."""
import asyncio
import sys
import json
sys.path.insert(0, "/home/claude/AegisLab/backend")

from models import ScanConfig, EndpointSpec, HttpMethod, ScanResult
from scanner import run_scan
from report_generator import export_json, export_pdf

config = ScanConfig(
    base_url="http://127.0.0.1:9000",
    bearer_token="fake.test.token",
    confirm_authorized=True,
    requests_per_second=15,
    endpoints=[
        EndpointSpec(path="/users/{id}", method=HttpMethod.GET, requires_auth=True),
        EndpointSpec(path="/auth/login", method=HttpMethod.POST, requires_auth=False,
                     request_body_sample={"email": "test@example.com", "password": "x"}),
        EndpointSpec(path="/search", method=HttpMethod.GET, requires_auth=False, params=["q"]),
        EndpointSpec(path="/admin/dashboard", method=HttpMethod.GET, requires_auth=True, tags=["admin"]),
    ],
)


async def main():
    final_result = None
    async for item in run_scan("smoke-test-scan", config):
        if isinstance(item, ScanResult):
            final_result = item
        else:
            print(f"[{item.status:9}] {item.module:25} {item.message}")
    print("\n=== SCAN COMPLETE ===")
    print(f"Security Score: {final_result.security_score}/100")
    print(f"Total findings: {len(final_result.vulnerabilities)}")
    for v in final_result.vulnerabilities:
        print(f"  - [{v.severity.value:8}] {v.test_module:22} {v.issue}")

    export_json(final_result, "/home/claude/AegisLab/examples/sample_scan_report.json")
    export_pdf(final_result, "/home/claude/AegisLab/examples/sample_scan_report.pdf")
    print("\nReports written to examples/")

asyncio.run(main())
