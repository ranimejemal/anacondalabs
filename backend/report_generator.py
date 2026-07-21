"""
AegisLab - report_generator.py
=================================
Generates the two exportable report formats:
  - JSON: machine-readable, exact schema from the spec
  - PDF: human-readable report with score, OWASP breakdown, and per-finding cards

Uses reportlab (pure-Python, no external binary dependency) so the PDF
pipeline works the same on Windows/macOS/Linux inside the Anaconda env.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)

from models import ScanResult, Severity
from scoring import grade_for_score

SEVERITY_COLOR = {
    "CRITICAL": colors.HexColor("#d92d3a"),
    "HIGH": colors.HexColor("#f0703c"),
    "MEDIUM": colors.HexColor("#f0b429"),
    "LOW": colors.HexColor("#3b9c6e"),
    "INFO": colors.HexColor("#6b7280"),
}

BRAND_DARK = colors.HexColor("#0b1320")
BRAND_ACCENT = colors.HexColor("#22d3ee")


def export_json(result: ScanResult, out_path: str | Path) -> Path:
    out_path = Path(out_path)
    payload = {
        "scan_id": result.scan_id,
        "base_url": result.base_url,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "status": result.status,
        "security_score": result.security_score,
        "grade": grade_for_score(result.security_score) if result.security_score is not None else None,
        "score_breakdown": result.score_breakdown,
        "endpoints_tested": result.endpoints_tested,
        "modules_run": result.modules_run,
        "vulnerabilities": [v.to_report_dict() for v in result.vulnerabilities],
        "generated_by": "AegisLab Security Engine",
    }
    out_path.write_text(json.dumps(payload, indent=2))
    return out_path


def export_pdf(result: ScanResult, out_path: str | Path) -> Path:
    out_path = Path(out_path)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle("AegisTitle", parent=styles["Title"], textColor=BRAND_DARK, fontSize=24)
    h2_style = ParagraphStyle("AegisH2", parent=styles["Heading2"], textColor=BRAND_DARK, spaceBefore=14)
    body_style = ParagraphStyle("AegisBody", parent=styles["BodyText"], fontSize=9.5, leading=13)
    small_style = ParagraphStyle("AegisSmall", parent=styles["BodyText"], fontSize=8, textColor=colors.grey)

    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        topMargin=22 * mm, bottomMargin=18 * mm, leftMargin=18 * mm, rightMargin=18 * mm,
        title="AegisLab Security Report",
    )

    elements = []

    # --- Cover / summary ---
    elements.append(Paragraph("AegisLab", title_style))
    elements.append(Paragraph("Automated API Security Test Report", h2_style))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(f"Target: {result.base_url}", body_style))
    elements.append(Paragraph(f"Scan ID: {result.scan_id}", small_style))
    elements.append(Paragraph(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}", small_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))
    elements.append(Spacer(1, 10))

    score = result.security_score if result.security_score is not None else 0
    grade = grade_for_score(score)
    summary_data = [
        ["Security Score", "Grade", "Endpoints Tested", "Total Findings"],
        [f"{score}/100", grade, str(result.endpoints_tested), str(len(result.vulnerabilities))],
    ]
    summary_table = Table(summary_data, colWidths=[110, 90, 120, 110])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 16))

    # --- Severity breakdown ---
    severity_totals = result.score_breakdown.get("_summary", {}).get("severity_totals", {})
    if severity_totals:
        elements.append(Paragraph("Findings by Severity", h2_style))
        sev_data = [["Severity", "Count"]] + [[k, str(v)] for k, v in severity_totals.items()]
        sev_table = Table(sev_data, colWidths=[200, 100])
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ]
        for i, row in enumerate(sev_data[1:], start=1):
            sev_name = row[0]
            if sev_name in SEVERITY_COLOR:
                style_cmds.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLOR[sev_name]))
                style_cmds.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
        sev_table.setStyle(TableStyle(style_cmds))
        elements.append(sev_table)
        elements.append(Spacer(1, 16))

    # --- OWASP category breakdown ---
    elements.append(Paragraph("OWASP Category Breakdown", h2_style))
    cat_rows = [["Category", "Findings", "Score Impact"]]
    for cat, info in result.score_breakdown.items():
        if cat == "_summary":
            continue
        cat_rows.append([cat, str(info["finding_count"]), f"-{info['deduction']}"])
    if len(cat_rows) > 1:
        cat_table = Table(cat_rows, colWidths=[260, 80, 90])
        cat_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(cat_table)
    else:
        elements.append(Paragraph("No findings recorded — no categories impacted.", body_style))

    elements.append(PageBreak())

    # --- Detailed findings ---
    elements.append(Paragraph("Detailed Findings", title_style))
    elements.append(Spacer(1, 8))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_vulns = sorted(result.vulnerabilities, key=lambda v: severity_order.get(v.severity.value, 5))

    if not sorted_vulns:
        elements.append(Paragraph("No vulnerabilities were detected during this scan.", body_style))

    for v in sorted_vulns:
        color = SEVERITY_COLOR.get(v.severity.value, colors.grey)
        header_style = ParagraphStyle(
            "FindingHeader", parent=styles["Heading3"], textColor=colors.white,
            backColor=color, fontSize=11, leftIndent=4, spaceAfter=0, spaceBefore=0,
        )
        elements.append(Paragraph(f"&nbsp;[{v.severity.value}] {v.issue}", header_style))
        elements.append(Spacer(1, 4))
        meta = f"<b>Endpoint:</b> {v.method} {v.endpoint} &nbsp;&nbsp; <b>OWASP:</b> {v.owasp_category} &nbsp;&nbsp; <b>Module:</b> {v.test_module}"
        elements.append(Paragraph(meta, small_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(f"<b>Description:</b> {v.description}", body_style))
        elements.append(Paragraph(f"<b>Impact:</b> {v.impact}", body_style))
        elements.append(Paragraph(f"<b>Recommendation:</b> {v.recommendation}", body_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))
        elements.append(Spacer(1, 10))

    elements.append(Spacer(1, 20))
    elements.append(Paragraph(
        "Generated by AegisLab — automated, non-destructive API security testing for developer-owned systems only.",
        small_style,
    ))

    doc.build(elements)
    return out_path
