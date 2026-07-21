"""
AegisLab - scanner.py
========================
Orchestrates a full scan: builds the API client, runs each enabled test
module in sequence (sequential, not parallel, to keep load on the target
predictable and polite), streams progress events, and computes the final
security score.

SAFETY GATE: run_scan() refuses to start unless config.confirm_authorized
is True. The desktop UI requires the user to explicitly check "I own this
API or am authorized to test it" before a scan can be triggered.
"""

from __future__ import annotations

import time
from typing import AsyncIterator

from models import ScanConfig, ScanResult, ScanProgressEvent, Vulnerability
from api_client import SafeApiClient
from scoring import compute_score
from tests import MODULE_REGISTRY


class AuthorizationRequiredError(Exception):
    """Raised when a scan is attempted without the explicit consent flag set."""
    pass


async def run_scan(scan_id: str, config: ScanConfig) -> AsyncIterator[ScanProgressEvent | ScanResult]:
    """
    Async generator: yields ScanProgressEvent objects as each module runs,
    and finally yields a single ScanResult as the last item.
    """
    if not config.confirm_authorized:
        raise AuthorizationRequiredError(
            "Scan refused: you must confirm you own this API or are explicitly "
            "authorized to test it before AegisLab will run."
        )

    result = ScanResult(scan_id=scan_id, base_url=config.base_url, started_at=time.time())
    client = SafeApiClient(
        base_url=config.base_url,
        bearer_token=config.bearer_token,
        requests_per_second=config.requests_per_second,
    )

    all_vulns: list[Vulnerability] = []
    modules_to_run = [m for m in config.modules_enabled if m in MODULE_REGISTRY]
    total = len(modules_to_run) or 1

    try:
        for idx, module_name in enumerate(modules_to_run):
            yield ScanProgressEvent(
                scan_id=scan_id, module=module_name, status="started",
                message=f"Running {module_name}...",
                percent=int((idx / total) * 100),
                findings_so_far=len(all_vulns),
            )
            try:
                module_cls = MODULE_REGISTRY[module_name]
                module = module_cls(client, config)
                findings = await module.run(config.endpoints)
                all_vulns.extend(findings)
                result.modules_run.append(module_name)
                yield ScanProgressEvent(
                    scan_id=scan_id, module=module_name, status="completed",
                    message=f"{module_name} complete — {len(findings)} finding(s)",
                    percent=int(((idx + 1) / total) * 100),
                    findings_so_far=len(all_vulns),
                )
            except Exception as e:
                yield ScanProgressEvent(
                    scan_id=scan_id, module=module_name, status="error",
                    message=f"{module_name} failed: {e}",
                    percent=int(((idx + 1) / total) * 100),
                    findings_so_far=len(all_vulns),
                )

        result.vulnerabilities = all_vulns
        result.endpoints_tested = len(config.endpoints)
        score, breakdown = compute_score(all_vulns)
        result.security_score = score
        result.score_breakdown = breakdown
        result.status = "completed"
        result.finished_at = time.time()
    finally:
        await client.close()

    yield result
