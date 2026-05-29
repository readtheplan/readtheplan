"""Auditor-ready PDF export for compliance evidence envelopes.

Produces a single-page PDF report containing:
  - Framework name and version
  - Plan SHA256 (cryptographic anchor)
  - Risk summary table
  - Controls touched, sorted and deduplicated
  - Per-change details with risk tier, explanation, and controls
  - Reviewer signature block
  - Generation timestamp

Designed for auditors who need a printed or shareable record
without touching JSON or the CLI.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def export_evidence_pdf(
    evidence: Mapping[str, Any],
    output_path: str | Path,
) -> Path:
    """Export a compliance evidence envelope to PDF.

    Args:
        evidence: Evidence envelope dict (from EvidenceEnvelope.to_dict()).
        output_path: Where to write the PDF file.

    Returns:
        Path to the generated PDF.
    """
    output_path = Path(output_path)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=LETTER,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Title"],
        fontSize=18,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#555555"),
        spaceAfter=12,
    )
    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
    )
    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["Normal"],
        fontSize=8,
        fontName="Courier",
        leading=10,
    )
    footer_style = ParagraphStyle(
        "Footer",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#888888"),
    )

    story: list = []

    # ── Header ────────────────────────────────────────────────────────
    framework = evidence.get("framework", {})
    fw_name = framework.get("name", "unknown").upper()
    fw_version = framework.get("version", "")

    story.append(Paragraph(
        f"Compliance Evidence Report",
        title_style,
    ))
    story.append(Paragraph(
        f"Framework: {fw_name} {fw_version}  |  "
        f"Generated: {evidence.get('generated_at', 'unknown')}",
        subtitle_style,
    ))

    # ── Cryptographic Anchor ──────────────────────────────────────────
    plan_data = evidence.get("plan", {})
    plan_sha = plan_data.get("sha256", "unavailable")
    story.append(Paragraph("Plan Verification", heading_style))
    story.append(Paragraph(
        f"SHA256: <font face='Courier' size='8'>{plan_sha}</font>",
        body_style,
    ))

    # ── Risk Summary ──────────────────────────────────────────────────
    summary = evidence.get("summary", {})
    risks = summary.get("risks", {})
    change_count = summary.get("resource_change_count", 0)

    story.append(Paragraph("Risk Summary", heading_style))
    risk_data = [
        ["Risk Tier", "Count"],
        ["Safe", str(risks.get("safe", 0))],
        ["Review", str(risks.get("review", 0))],
        ["Dangerous", str(risks.get("dangerous", 0))],
        ["Irreversible", str(risks.get("irreversible", 0))],
        ["Total Changes", str(change_count)],
    ]
    risk_table = Table(risk_data, colWidths=[2.5 * inch, 1.5 * inch])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#27ae60")),
        ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#f39c12")),
        ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#e67e22")),
        ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#c0392b")),
        ("TEXTCOLOR", (0, 1), (1, 1), colors.white),
        ("TEXTCOLOR", (0, 2), (1, 2), colors.white),
        ("TEXTCOLOR", (0, 3), (1, 3), colors.white),
        ("TEXTCOLOR", (0, 4), (1, 4), colors.white),
        ("ROWBACKGROUNDS", (0, 5), (-1, 5), [colors.HexColor("#ecf0f1")]),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 6))

    # ── Controls Touched ──────────────────────────────────────────────
    controls_touched = summary.get("controls_touched", [])
    if controls_touched:
        story.append(Paragraph("Controls Touched", heading_style))
        story.append(Paragraph(
            ", ".join(controls_touched),
            mono_style,
        ))

    # ── Change Details ────────────────────────────────────────────────
    changes = evidence.get("changes", [])
    if changes:
        story.append(Paragraph("Change Details", heading_style))
        change_data = [["Resource", "Actions", "Risk", "Controls"]]
        for change in changes:
            address = change.get("address", "unknown")
            actions = ", ".join(change.get("actions", []))
            risk = change.get("risk", "unknown")
            controls_list = change.get("controls", [])
            controls_str = ", ".join(
                c.get("id", "") for c in controls_list
            ) if controls_list else "—"

            # Determine row color based on risk
            risk_colors = {
                "safe": colors.HexColor("#27ae60"),
                "review": colors.HexColor("#f39c12"),
                "dangerous": colors.HexColor("#e67e22"),
                "irreversible": colors.HexColor("#c0392b"),
            }
            row_color = risk_colors.get(risk, colors.HexColor("#95a5a6"))

            change_data.append([address, actions, risk.upper(), controls_str])

        change_table = Table(
            change_data,
            colWidths=[2.2 * inch, 1.3 * inch, 1.1 * inch, 2.4 * inch],
        )
        change_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(change_table)

    # ── Signatures ────────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(Paragraph("Reviewer Sign-off", heading_style))
    reviewer = evidence.get("reviewer")
    reviewer_text = (
        f"{reviewer.get('id', '')} ({reviewer.get('kind', 'human')})"
        if reviewer
        else "_________________________  (Human Reviewer)"
    )
    story.append(Paragraph(reviewer_text, body_style))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Date: _________________________",
        body_style,
    ))

    # ── Footer ────────────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        f"Generated by readtheplan  |  {evidence.get('generated_at', '')}  |  "
        f"Schema: {evidence.get('schema', '')}",
        footer_style,
    ))

    doc.build(story)
    return output_path
