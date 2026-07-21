"""
AegisLab - scoring.py
=======================
Computes a 0-100 "Security Score" from a list of findings, plus a
per-OWASP-category breakdown used by the dashboard's radar/bar chart.

Methodology (documented so the score is explainable, not a black box):
  - Start at 100.
  - Each finding deducts points based on severity, with diminishing
    returns per category so that e.g. 10 LOW findings in the same
    category don't outweigh a single CRITICAL elsewhere.
  - Final score is clamped to [0, 100].
  - A letter grade is derived for the dashboard header.
"""

from __future__ import annotations

from models import Vulnerability, Severity

BASE_PENALTY = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

# Diminishing returns: the Nth finding in the same OWASP category counts
# for less, so one category with many small issues doesn't dominate the score.
DIMINISHING_FACTOR = 0.6


def grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def compute_score(vulnerabilities: list[Vulnerability]) -> tuple[int, dict]:
    """Returns (score, breakdown) where breakdown is per-OWASP-category detail."""
    by_category: dict[str, list[Vulnerability]] = {}
    for v in vulnerabilities:
        by_category.setdefault(v.owasp_category, []).append(v)

    total_deduction = 0.0
    breakdown = {}

    for category, findings in by_category.items():
        findings_sorted = sorted(findings, key=lambda f: BASE_PENALTY[f.severity], reverse=True)
        category_deduction = 0.0
        for idx, finding in enumerate(findings_sorted):
            weight = DIMINISHING_FACTOR ** idx
            category_deduction += BASE_PENALTY[finding.severity] * weight

        total_deduction += category_deduction
        severity_counts = {s.value: sum(1 for f in findings if f.severity == s) for s in Severity}
        breakdown[category] = {
            "finding_count": len(findings),
            "deduction": round(category_deduction, 1),
            "severity_counts": {k: v for k, v in severity_counts.items() if v > 0},
        }

    score = max(0, min(100, round(100 - total_deduction)))
    breakdown["_summary"] = {
        "total_findings": len(vulnerabilities),
        "grade": grade_for_score(score),
        "severity_totals": {
            s.value: sum(1 for v in vulnerabilities if v.severity == s) for s in Severity
            if sum(1 for v in vulnerabilities if v.severity == s) > 0
        },
    }
    return score, breakdown
