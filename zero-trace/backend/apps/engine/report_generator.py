"""Redacted PDF privacy report generation."""

from __future__ import annotations

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .redaction import redact_label

ACCENT = colors.HexColor("#00E5A8")
DARK = colors.HexColor("#0B1120")
MUTED = colors.HexColor("#5B6B84")
LIGHT = colors.HexColor("#EEF3F8")


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ZT_Title", parent=styles["Title"], fontSize=22, textColor=DARK, spaceAfter=4))
    styles.add(ParagraphStyle(name="ZT_Sub", parent=styles["Normal"], fontSize=9, textColor=MUTED, spaceAfter=12))
    styles.add(ParagraphStyle(name="ZT_Head", parent=styles["Heading2"], fontSize=13, textColor=DARK, spaceBefore=12, spaceAfter=6))
    styles.add(ParagraphStyle(name="ZT_Body", parent=styles["Normal"], fontSize=9, leading=13, alignment=TA_LEFT))
    styles.add(ParagraphStyle(name="ZT_Cell", parent=styles["Normal"], fontSize=8, leading=11))
    styles.add(ParagraphStyle(name="ZT_CellHead", parent=styles["Normal"], fontSize=8, leading=11, textColor=colors.white))
    return styles


def generate_report(scan, findings, recommendations) -> bytes:
    """Build a PDF containing redacted evidence only."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="ZeroTrace Privacy Report",
        author="ZeroTrace",
    )
    styles = _styles()
    story = []

    story.append(Paragraph("ZEROTRACE PRIVACY REPORT", styles["ZT_Title"]))
    story.append(
        Paragraph(
            f"Source: {redact_label(scan.source_name)} &nbsp;|&nbsp; Type: {scan.scan_type} &nbsp;|&nbsp; "
            f"Generated: {scan.created_at:%Y-%m-%d %H:%M UTC} &nbsp;|&nbsp; Scan ID: {scan.id}",
            styles["ZT_Sub"],
        )
    )

    summary = scan.summary or {}
    risk_table = Table(
        [
            ["Risk score", f"{scan.risk_score}/100"],
            ["Risk level", scan.risk_level.upper()],
            ["Total findings", str(summary.get("total", 0))],
            ["Critical findings", str(summary.get("critical_count", 0))],
        ],
        colWidths=[45 * mm, 130 * mm],
    )
    risk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), LIGHT),
                ("TEXTCOLOR", (0, 0), (0, -1), DARK),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D8E0EA")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(risk_table)

    narrative = scan.ai_summary or "No narrative available."
    story.append(Paragraph("Assessment", styles["ZT_Head"]))
    story.append(Paragraph(narrative.replace("\n", "<br/>"), styles["ZT_Body"]))

    story.append(Paragraph("Findings (all values redacted)", styles["ZT_Head"]))
    header = [Paragraph(text, styles["ZT_CellHead"]) for text in ("Severity", "Category", "Finding", "Location", "Evidence", "Remediation")]
    rows = [header]
    for finding in findings:
        rows.append(
            [
                Paragraph(finding.severity.upper(), styles["ZT_Cell"]),
                Paragraph(finding.category.replace("_", " "), styles["ZT_Cell"]),
                Paragraph(finding.title, styles["ZT_Cell"]),
                Paragraph(finding.location or "-", styles["ZT_Cell"]),
                Paragraph(finding.redacted_evidence or "-", styles["ZT_Cell"]),
                Paragraph(finding.remediation or "-", styles["ZT_Cell"]),
            ]
        )
    if len(rows) == 1:
        rows.append([Paragraph("-", styles["ZT_Cell"])] * 6)
    table = Table(rows, colWidths=[17 * mm, 22 * mm, 36 * mm, 27 * mm, 34 * mm, 39 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D8E0EA")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(table)

    story.append(Paragraph("Recommended actions", styles["ZT_Head"]))
    for index, recommendation in enumerate(recommendations, start=1):
        story.append(Paragraph(f"<b>{index}. {recommendation.title}</b>", styles["ZT_Body"]))
        story.append(Paragraph(recommendation.description, styles["ZT_Body"]))
        story.append(Spacer(1, 4))

    story.append(Spacer(1, 10))
    story.append(
        Paragraph(
            "Privacy notice: this report contains only redacted evidence and one-way fingerprints. "
            "No raw secrets, document contents or uploaded files were transmitted to external AI services without explicit consent.",
            styles["ZT_Sub"],
        )
    )

    doc.build(story)
    return buffer.getvalue()
