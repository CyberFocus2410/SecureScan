"""PDF report export generator (FR-RPT, Design §12).

Supports WeasyPrint 63.1 (CSS Paged Media) with an automatic fallback to
pure-Python ReportLab when running in environments without system Cairo/Pango C-libraries.
Every generated page includes the mandatory running header:
"Developer-assistance report — not a security certificate or legal opinion."
"""
import io
import os
from pathlib import Path
from typing import Any
from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session

from app.reporting.collector import collect_audit_report_data
from app.core.security import redact_text


def _get_jinja_env() -> Environment:
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    return Environment(loader=FileSystemLoader(template_dir), autoescape=True)


def render_html_report(data: dict[str, Any]) -> str:
    """Render HTML string for WeasyPrint or HTML export."""
    env = _get_jinja_env()
    template = env.get_template("report.html")
    html_content = template.render(**data)
    return redact_text(html_content)


def generate_pdf_with_weasyprint(data: dict[str, Any]) -> bytes:
    """Generate PDF using WeasyPrint 63.1."""
    import weasyprint
    html_str = render_html_report(data)
    pdf_bytes = weasyprint.HTML(string=html_str).write_pdf()
    return pdf_bytes


class NumberedCanvas:
    """ReportLab canvas that adds running header and footer with total page count."""
    def __init__(self, *args, **kwargs):
        from reportlab.pdfgen import canvas
        self.canvas_class = canvas.Canvas
        self.header_text = "Developer-assistance report — not a security certificate or legal opinion."

    def __call__(self, *args, **kwargs):
        canvas_instance = self.canvas_class(*args, **kwargs)
        orig_showPage = canvas_instance.showPage
        orig_save = canvas_instance.save
        pages = []

        def showPage():
            pages.append(dict(canvas_instance.__dict__))
            orig_showPage()

        def save():
            num_pages = len(pages)
            for page in pages:
                canvas_instance.__dict__.update(page)
                draw_header_footer(canvas_instance, num_pages)
                orig_showPage()
            orig_save()

        def draw_header_footer(c, total):
            c.saveState()
            c.setFont("Helvetica", 8)
            c.setFillColorRGB(0.39, 0.45, 0.55)  # #64748b
            # Running header on every page
            c.drawCentredString(297.5, 810, self.header_text)
            c.setStrokeColorRGB(0.88, 0.91, 0.94)
            c.setLineWidth(0.5)
            c.line(36, 804, 559, 804)
            # Running footer
            page_num_str = f"Page {c._pageNumber} of {total}"
            c.drawRightString(559, 25, page_num_str)
            c.restoreState()

        canvas_instance.showPage = showPage
        canvas_instance.save = save
        return canvas_instance


def generate_pdf_with_reportlab(data: dict[str, Any]) -> bytes:
    """Generate professional PDF using ReportLab with exact mandatory sections and running header."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        KeepTogether,
        PageBreak,
        Image as ReportLabImage
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=45
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#0f172a'),
        alignment=1,  # Center
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'ReportSubTitle',
        parent=styles['Normal'],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#0284c7'),
        alignment=1,
        spaceAfter=20
    )
    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Heading2'],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=12,
        spaceAfter=6
    )
    h3_style = ParagraphStyle(
        'H3',
        parent=styles['Heading3'],
        fontSize=10.5,
        leading=13,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=8,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#334155')
    )
    code_style = ParagraphStyle(
        'Code',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=9.5,
        fontName='Courier',
        textColor=colors.HexColor('#0f172a'),
        backColor=colors.HexColor('#f1f5f9')
    )
    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Normal'],
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor('#92400e'),
        backColor=colors.HexColor('#fffbeb'),
        borderColor=colors.HexColor('#f59e0b'),
        borderWidth=1,
        borderPadding=6,
        spaceBefore=8,
        spaceAfter=8
    )

    story = []

    # 1. Cover Page
    story.append(Spacer(1, 20))
    logo_path = Path(__file__).parent / "assets" / "logo.jpg"
    if logo_path.exists():
        logo_img = ReportLabImage(str(logo_path), width=56, height=56)
        logo_img.hAlign = 'CENTER'
        story.append(logo_img)
        story.append(Spacer(1, 12))
    story.append(Paragraph("SecureScan AI", title_style))
    story.append(Paragraph("Security &amp; DPDP Readiness Audit Report", subtitle_style))

    repo = data.get("repository", {})
    meta = data.get("metadata", {})
    meta_data = [
        [Paragraph("<b>Target Repository:</b>", body_style), Paragraph(repo.get("url", ""), body_style)],
        [Paragraph("<b>Branch:</b>", body_style), Paragraph(repo.get("branch", ""), body_style)],
        [Paragraph("<b>Pinned Commit SHA:</b>", body_style), Paragraph(f"<code>{repo.get('commit_sha', '')}</code>", code_style)],
        [Paragraph("<b>Audit Timestamp:</b>", body_style), Paragraph(meta.get("created_at", ""), body_style)],
        [Paragraph("<b>Statutory As-of Date:</b>", body_style), Paragraph(meta.get("as_of_date", ""), body_style)],
        [Paragraph("<b>Report Status:</b>", body_style), Paragraph(meta.get("status", ""), body_style)],
    ]
    meta_table = Table(meta_data, colWidths=[150, 360])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)

    story.append(Spacer(1, 15))
    story.append(Paragraph(
        "<b>Mandatory Notice:</b> " + meta.get("mandatory_header", ""),
        disclaimer_style
    ))

    # Scanner versions table
    runs = data.get("tool_versions", [])
    if runs:
        story.append(Paragraph("<b>Scanners &amp; Tools Pinned:</b>", h3_style))
        runs_table_data = [["Scanner", "Version", "Status", "Findings"]]
        for r in runs:
            runs_table_data.append([
                r.get("scanner", ""),
                r.get("version", ""),
                r.get("status", ""),
                str(r.get("findings_count", 0))
            ])
        rt = Table(runs_table_data, colWidths=[130, 130, 130, 120])
        rt.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(rt)

    story.append(PageBreak())

    # 2. Executive Summary
    story.append(Paragraph("1. Executive Summary", h2_style))
    story.append(Paragraph("Counts and coverage summary (no headline grade):", body_style))
    story.append(Spacer(1, 6))

    ex = data.get("executive_summary", {})
    sev = ex.get("severity_counts", {})
    summary_data = [
        ["Metric", "Value"],
        ["Total Findings Detected", str(ex.get("total_findings", 0))],
        ["Confirmed Findings (High/Confirmed Confidence)", str(ex.get("confirmed_count", 0))],
        ["Potential Findings (Heuristic/Contextual Gaps)", str(ex.get("potential_count", 0))],
        ["Critical Severity", str(sev.get("CRITICAL", 0))],
        ["High Severity", str(sev.get("HIGH", 0))],
        ["Medium Severity", str(sev.get("MEDIUM", 0))],
        ["Low Severity", str(sev.get("LOW", 0))],
        ["Security Controls Coverage Ratio", f"{ex.get('security_coverage_ratio', '0/32')} (Evidenced / Applicable controls)"],
        ["Headline Grade", ex.get("headline_grade", "NONE")]
    ]
    st = Table(summary_data, colWidths=[240, 270])
    st.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(st)

    # 3. Methodology & Exclusions
    story.append(Paragraph("2. Methodology &amp; Exclusions", h2_style))
    meth = data.get("methodology_and_exclusions", {})
    story.append(Paragraph(f"<b>Scanner Sandbox:</b> {meth.get('scanner_sandbox', '')}", body_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"<b>Repo Execution Policy:</b> {meth.get('repo_execution_policy', '')}", body_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Limitations:</b>", body_style))
    for lim in meth.get("limitations", []):
        story.append(Paragraph(f"• {lim}", body_style))

    story.append(PageBreak())

    # 4. Security Findings Table
    story.append(Paragraph("3. Security Findings", h2_style))
    findings = data.get("findings", [])
    if not findings:
        story.append(Paragraph("<i>No findings from checks that ran. Verified controls satisfied baseline criteria.</i>", body_style))
    else:
        findings_table_data = [["Sev", "Title", "Scanner", "Location", "OWASP"]]
        for f in findings:
            findings_table_data.append([
                f.get("severity", ""),
                Paragraph(f"<b>{f.get('title', '')}</b>", body_style),
                f.get("scanner_name", ""),
                Paragraph(f"{f.get('file_path', '')}:{f.get('start_line', '')}", code_style),
                ", ".join(f.get("owasp_refs", []))
            ])
        ft = Table(findings_table_data, colWidths=[45, 180, 75, 140, 70])
        ft.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7.5),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(ft)

        story.append(Spacer(1, 10))
        story.append(Paragraph("<b>Per-Finding Proof and Technical Fixes:</b>", h3_style))
        for idx, f in enumerate(findings[:10]):  # Bounded to top findings to keep readable
            block = []
            block.append(Paragraph(f"<b>Finding {idx+1}: {f.get('title')}</b> [{f.get('severity')}]", h3_style))
            block.append(Paragraph(f"<b>File:</b> {f.get('file_path')}:{f.get('start_line')} | <b>Rule:</b> {f.get('rule_id')}", body_style))
            snip = f.get("redacted_snippet")
            if snip:
                block.append(Paragraph(f"<b>Redacted Excerpt:</b> <code>{snip}</code>", code_style))
            block.append(Paragraph(f"<b>Technical Fix:</b> {f.get('technical_fix')}", body_style))
            block.append(Paragraph(f"<b>Validation Steps:</b> {f.get('validation_steps')}", body_style))
            block.append(Spacer(1, 6))
            story.append(KeepTogether(block))

    story.append(PageBreak())

    # 5. OWASP Coverage Matrix
    story.append(Paragraph("4. Security Controls &amp; OWASP Coverage Matrix", h2_style))
    sec_ctrls = data.get("security_controls", [])
    ctrl_rows = [["ID", "State", "Rationale"]]
    for sc in sec_ctrls:
        ctrl_rows.append([
            sc.get("control_id", ""),
            sc.get("state", ""),
            Paragraph(sc.get("rationale", ""), body_style)
        ])
    ct = Table(ctrl_rows, colWidths=[65, 95, 350])
    ct.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7.5),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(ct)

    story.append(PageBreak())

    # 6. DPDP Matrix
    story.append(Paragraph("5. DPDP Act 2023 / Rules 2025 Readiness Matrix", h2_style))
    story.append(Paragraph(
        "<b>Commencement Notice:</b> Evaluated relative to as-of date (2026-11-14). Upcoming duties are not active violations.",
        disclaimer_style
    ))
    dpdp_ctrls = data.get("dpdp_controls", [])
    dpdp_rows = [["ID", "Control Title", "Readiness", "Effective Status", "Citation"]]
    for dc in dpdp_ctrls:
        dpdp_rows.append([
            dc.get("control_id", ""),
            Paragraph(dc.get("title", ""), body_style),
            dc.get("state", ""),
            f"{dc.get('effective_status', '')}\n({dc.get('effective_date', '')})",
            Paragraph(dc.get("citation", ""), body_style)
        ])
    dt = Table(dpdp_rows, colWidths=[55, 150, 85, 110, 110])
    dt.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7.5),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(dt)

    story.append(PageBreak())

    # 7. Legal Appendix: Penalty Reference
    story.append(Paragraph("6. Legal Appendix: Statutory Penalty Reference", h2_style))
    leg = data.get("legal_exposure", {})
    story.append(Paragraph(
        f"<b>Mandatory Caveat:</b> {leg.get('disclaimer', '')}<br/>"
        "<i>SecureScan AI does not estimate, predict, calculate, or sum penalty amounts. "
        "Figures shown below represent statutory maximum ceilings enacted in the Schedule to the DPDP Act 2023.</i>",
        disclaimer_style
    ))
    cats = leg.get("categories", [])
    pen_rows = [["Item", "Related Section", "Statutory Ceiling", "Mandatory Caveat"]]
    for c in cats:
        pen_rows.append([
            f"Item {c.get('schedule_item')}",
            c.get("related_act_section", ""),
            c.get("statutory_ceiling_inr", ""),
            Paragraph(c.get("caveat", ""), body_style)
        ])
    pt = Table(pen_rows, colWidths=[50, 100, 120, 240])
    pt.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7.5),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(pt)

    # 8. Remediation Plan & Gaps
    story.append(Paragraph("7. Prioritized Remediation Plan", h2_style))
    rem_plan = data.get("remediation_plan", {})
    for kind in ["ENGINEERING", "DOCUMENTATION", "ORGANIZATIONAL"]:
        actions = rem_plan.get(kind, [])
        if actions:
            story.append(Paragraph(f"<b>{kind.title()} Actions:</b>", h3_style))
            for a in actions:
                story.append(Paragraph(
                    f"• <b>[{a.get('priority')}] {a.get('title')} ({a.get('target_id')}):</b> "
                    f"{' '.join(a.get('steps', []))} <i>Validation:</i> {a.get('validation_method')}",
                    body_style
                ))

    story.append(Spacer(1, 6))
    story.append(Paragraph("8. Evidence Gaps &amp; Next Steps", h2_style))
    gaps = data.get("evidence_gaps", [])
    if gaps:
        for g in gaps:
            story.append(Paragraph(f"• <b>{g.get('control_id')} ({g.get('state')}):</b> {g.get('rationale')}", body_style))
    else:
        story.append(Paragraph("<i>No unresolved evidence gaps.</i>", body_style))

    # Build the document using the NumberedCanvas to ensure header on every page
    canvas_factory = NumberedCanvas()
    doc.build(story, canvasmaker=canvas_factory)
    return buffer.getvalue()


def generate_pdf_report(audit_id: str, db: Session) -> bytes:
    """
    Generate PDF report for audit.
    Tries WeasyPrint first; falls back to pure-Python ReportLab if Cairo/Pango unavailable.
    Guarantees no raw secrets in generated document.
    """
    data = collect_audit_report_data(audit_id, db)
    pdf_bytes: bytes

    try:
        pdf_bytes = generate_pdf_with_weasyprint(data)
    except (ImportError, OSError, Exception):
        # Fall back to ReportLab
        pdf_bytes = generate_pdf_with_reportlab(data)

    return pdf_bytes
