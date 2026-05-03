"""
=============================================================================
report_gen.py - PDF Report Generator v11.0
AI-Powered Vulnerability Assessment System — FYP
=============================================================================
PDF Design:
  • Header box      : Blue (#1565C0) background, white text
  • Body background : White
  • Body text       : Black (#000000)
  • Section headers : Blue (#1565C0)
  • Risk colors     : Red/Orange/Yellow/Green
=============================================================================
"""

import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak,
    )
    from reportlab.platypus.flowables import KeepTogether
    REPORTLAB_AVAILABLE = True
    logger.info("ReportLab available — PDF generation enabled.")
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("ReportLab not installed. PDF generation disabled.")

# ── Design Colors ──────────────────────────────────────────────────────────
BLUE_DARK   = "#1565C0"   # Header background
BLUE_MED    = "#1976D2"   # Section headers
BLUE_LIGHT  = "#E3F2FD"   # Alternating row tint
WHITE       = "#FFFFFF"   # Page / cell background
BLACK       = "#000000"   # Body text
GREY_LINE   = "#BDBDBD"   # Dividers

RISK_HEX = {
    "CRITICAL": "#C62828",
    "HIGH":     "#E65100",
    "MEDIUM":   "#F9A825",
    "LOW":      "#2E7D32",
}
RISK_BG_HEX = {
    "CRITICAL": "#FFCDD2",
    "HIGH":     "#FFE0B2",
    "MEDIUM":   "#FFF9C4",
    "LOW":      "#C8E6C9",
}


class ReportGenerator:
    """PDF report with blue header, white background, black text."""

    def __init__(self, scan_results: dict, risk_assessment: dict):
        self.scan  = scan_results
        self.risk  = risk_assessment
        self.styles = getSampleStyleSheet() if REPORTLAB_AVAILABLE else None
        self._setup_styles()

    # ── Styles ──────────────────────────────────────────────────────────────
    def _setup_styles(self):
        if not REPORTLAB_AVAILABLE:
            return

        def _ps(name, parent="Normal", **kw):
            base = self.styles.get(parent, self.styles["Normal"])
            return ParagraphStyle(name, parent=base, **kw)

        self.s_title = _ps("S_Title",
            fontSize=20, textColor=colors.white,
            fontName="Helvetica-Bold", alignment=TA_CENTER,
            spaceAfter=4)

        self.s_subtitle = _ps("S_Sub",
            fontSize=10, textColor=colors.HexColor("#BBDEFB"),
            fontName="Helvetica", alignment=TA_CENTER)

        self.s_section = _ps("S_Sec",
            fontSize=13, textColor=colors.HexColor(BLUE_MED),
            fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6,
            borderPad=2)

        self.s_body = _ps("S_Body",
            fontSize=10, textColor=colors.HexColor(BLACK),
            fontName="Helvetica", spaceAfter=4, leading=14)

        self.s_meta_key = _ps("S_MetaKey",
            fontSize=9, textColor=colors.HexColor(BLUE_DARK),
            fontName="Helvetica-Bold")

        self.s_meta_val = _ps("S_MetaVal",
            fontSize=9, textColor=colors.HexColor(BLACK),
            fontName="Helvetica")

        self.s_table_hdr = _ps("S_TblHdr",
            fontSize=9, textColor=colors.white,
            fontName="Helvetica-Bold", alignment=TA_CENTER)

        self.s_table_cell = _ps("S_TblCell",
            fontSize=9, textColor=colors.HexColor(BLACK),
            fontName="Helvetica")

        self.s_risk_label = _ps("S_Risk",
            fontSize=28, fontName="Helvetica-Bold",
            alignment=TA_CENTER)

        self.s_footer = _ps("S_Footer",
            fontSize=8, textColor=colors.grey,
            fontName="Helvetica", alignment=TA_CENTER)

    # ── Header ──────────────────────────────────────────────────────────────
    def _build_header(self):
        if not REPORTLAB_AVAILABLE:
            return []
        elems = []

        # Blue header box
        title_data = [[
            Paragraph("AI-Powered Vulnerability Assessment System", self.s_title),
            Paragraph("FYP — Computer Science Department", self.s_subtitle),
        ]]
        # Flatten into two rows
        hdr_data = [
            [Paragraph("🛡  AI-Powered Vulnerability Assessment System", self.s_title)],
            [Paragraph("Final Year Project  |  Computer Science  |  v11.0", self.s_subtitle)],
        ]
        hdr_tbl = Table(hdr_data, colWidths=[17*cm])
        hdr_tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,-1), colors.HexColor(BLUE_DARK)),
            ("TEXTCOLOR",   (0,0), (-1,-1), colors.white),
            ("ALIGN",       (0,0), (-1,-1), "CENTER"),
            ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",  (0,0), (-1,-1), 18),
            ("BOTTOMPADDING",(0,0),(-1,-1), 18),
            ("LEFTPADDING", (0,0), (-1,-1), 20),
            ("RIGHTPADDING",(0,0), (-1,-1), 20),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.HexColor(BLUE_DARK)]),
            ("LINEBELOW",   (0,1), (-1,1), 3, colors.HexColor("#42A5F5")),
        ]))
        elems.append(hdr_tbl)
        elems.append(Spacer(1, 0.4*cm))

        # Generated date bar
        now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        date_data = [[f"Report Generated: {now}  |  Prepared by: FYP Security Suite"]]
        date_tbl  = Table(date_data, colWidths=[17*cm])
        date_tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0,0),(-1,-1), colors.HexColor("#E3F2FD")),
            ("TEXTCOLOR",   (0,0),(-1,-1), colors.HexColor(BLUE_DARK)),
            ("FONTNAME",    (0,0),(-1,-1), "Helvetica"),
            ("FONTSIZE",    (0,0),(-1,-1), 8),
            ("ALIGN",       (0,0),(-1,-1), "CENTER"),
            ("TOPPADDING",  (0,0),(-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1), 4),
        ]))
        elems.append(date_tbl)
        elems.append(Spacer(1, 0.5*cm))
        return elems

    # ── Section divider ──────────────────────────────────────────────────────
    def _section(self, title):
        elems = []
        elems.append(HRFlowable(width="100%", thickness=1,
                                color=colors.HexColor(BLUE_MED),
                                spaceAfter=4))
        data = [[Paragraph("  " + title, self.s_table_hdr)]]
        tbl  = Table(data, colWidths=[17*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0,0),(-1,-1), colors.HexColor(BLUE_MED)),
            ("TOPPADDING",   (0,0),(-1,-1), 6),
            ("BOTTOMPADDING",(0,0),(-1,-1), 6),
            ("LEFTPADDING",  (0,0),(-1,-1), 8),
        ]))
        elems.append(tbl)
        elems.append(Spacer(1, 0.25*cm))
        return elems

    # ── Metadata table ───────────────────────────────────────────────────────
    def _build_metadata(self):
        if not REPORTLAB_AVAILABLE:
            return []
        elems = self._section("SCAN INFORMATION")
        scan = self.scan or {}
        meta = [
            ["Target IP",    scan.get("target_ip", "N/A")],
            ["Hostname",     scan.get("hostname",  "N/A")],
            ["OS",           scan.get("os",        "N/A")],
            ["Scan Date",    scan.get("scan_date", datetime.now().strftime("%Y-%m-%d %H:%M"))],
            ["Duration",     scan.get("duration",  "N/A")],
            ["Open Ports",   str(len(scan.get("open_ports",[]) or []))],
        ]
        rows = [[Paragraph(k, self.s_meta_key), Paragraph(str(v), self.s_meta_val)]
                for k,v in meta]
        tbl = Table(rows, colWidths=[5*cm, 12*cm])
        row_bgs = []
        for i in range(len(rows)):
            bg = colors.HexColor(BLUE_LIGHT) if i % 2 == 0 else colors.white
            row_bgs.append(("BACKGROUND", (0,i),(-1,i), bg))
        tbl.setStyle(TableStyle([
            ("FONTNAME",    (0,0),(-1,-1), "Helvetica"),
            ("FONTSIZE",    (0,0),(-1,-1), 9),
            ("TEXTCOLOR",   (0,0),(0,-1),  colors.HexColor(BLUE_DARK)),
            ("TEXTCOLOR",   (1,0),(1,-1),  colors.HexColor(BLACK)),
            ("GRID",        (0,0),(-1,-1), 0.5, colors.HexColor(GREY_LINE)),
            ("TOPPADDING",  (0,0),(-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING", (0,0),(-1,-1), 8),
        ] + row_bgs))
        elems.append(tbl)
        elems.append(Spacer(1, 0.4*cm))
        return elems

    # ── Risk summary ─────────────────────────────────────────────────────────
    def _build_risk_summary(self):
        if not REPORTLAB_AVAILABLE:
            return []
        elems = self._section("RISK ASSESSMENT SUMMARY")
        risk  = self.risk or {}
        score = risk.get("score", 0)
        level = risk.get("level", "LOW")
        color = colors.HexColor(RISK_HEX.get(level, "#2E7D32"))
        bg    = colors.HexColor(RISK_BG_HEX.get(level, "#C8E6C9"))

        # Big score box
        score_style = ParagraphStyle("ScoreS", parent=self.s_risk_label,
                                     textColor=color)
        level_style = ParagraphStyle("LevelS", parent=self.s_table_hdr,
                                     textColor=color, fontSize=14)
        data = [
            [Paragraph(str(score), score_style)],
            [Paragraph(level + "  RISK", level_style)],
        ]
        tbl = Table(data, colWidths=[17*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0,0),(-1,-1), bg),
            ("ALIGN",        (0,0),(-1,-1), "CENTER"),
            ("TOPPADDING",   (0,0),(-1,-1), 16),
            ("BOTTOMPADDING",(0,0),(-1,-1), 16),
            ("BOX",          (0,0),(-1,-1), 2, color),
        ]))
        elems.append(tbl)
        elems.append(Spacer(1, 0.4*cm))

        # Summary text
        summary = risk.get("summary","No summary available.")
        elems.append(Paragraph(str(summary), self.s_body))
        elems.append(Spacer(1, 0.3*cm))
        return elems

    # ── Risk factors table ───────────────────────────────────────────────────
    def _build_factors(self):
        if not REPORTLAB_AVAILABLE:
            return []
        elems = self._section("RISK FACTOR ANALYSIS")
        factors = (self.risk or {}).get("factors", [])
        if not factors:
            elems.append(Paragraph("No factors available.", self.s_body))
            return elems

        hdr = [Paragraph(h, self.s_table_hdr) for h in
               ["Factor", "Status", "Severity", "Score"]]
        rows = [hdr]
        for f in factors:
            sev  = f.get("severity","LOW")
            bg   = colors.HexColor(RISK_BG_HEX.get(sev, WHITE))
            row  = [
                Paragraph(str(f.get("name","")),     self.s_table_cell),
                Paragraph(str(f.get("status","")),   self.s_table_cell),
                Paragraph(sev,                        self.s_table_cell),
                Paragraph(str(f.get("score","")),     self.s_table_cell),
            ]
            rows.append(row)

        tbl = Table(rows, colWidths=[6*cm, 5*cm, 3*cm, 3*cm])
        style_cmds = [
            ("BACKGROUND",   (0,0),(-1,0),  colors.HexColor(BLUE_DARK)),
            ("TEXTCOLOR",    (0,0),(-1,0),  colors.white),
            ("FONTNAME",     (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTNAME",     (0,1),(-1,-1), "Helvetica"),
            ("FONTSIZE",     (0,0),(-1,-1), 9),
            ("GRID",         (0,0),(-1,-1), 0.5, colors.HexColor(GREY_LINE)),
            ("ALIGN",        (2,0),(-1,-1), "CENTER"),
            ("TOPPADDING",   (0,0),(-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING",  (0,0),(-1,-1), 6),
        ]
        for i, f in enumerate(factors, start=1):
            sev = f.get("severity","LOW")
            style_cmds.append(("BACKGROUND",(0,i),(-1,i),
                               colors.HexColor(RISK_BG_HEX.get(sev,WHITE))))
        tbl.setStyle(TableStyle(style_cmds))
        elems.append(tbl)
        elems.append(Spacer(1, 0.4*cm))
        return elems

    # ── Open ports ───────────────────────────────────────────────────────────
    def _build_ports(self):
        if not REPORTLAB_AVAILABLE:
            return []
        elems = self._section("OPEN PORTS DETECTED")
        ports = (self.scan or {}).get("open_ports", [])
        if not ports:
            elems.append(Paragraph("No open ports detected.", self.s_body))
            return elems

        hdr  = [Paragraph(h, self.s_table_hdr)
                for h in ["Port","Service","Risk","Recommendation"]]
        rows = [hdr]
        for p in ports:
            port_no = str(p.get("port",""))
            service = str(p.get("service",""))
            risk    = str(p.get("risk","LOW"))
            rec     = str(p.get("recommendation","Review and restrict if not needed."))
            rows.append([
                Paragraph(port_no, self.s_table_cell),
                Paragraph(service, self.s_table_cell),
                Paragraph(risk,    self.s_table_cell),
                Paragraph(rec,     self.s_table_cell),
            ])

        tbl = Table(rows, colWidths=[2*cm, 4*cm, 2.5*cm, 8.5*cm])
        style_cmds = [
            ("BACKGROUND",   (0,0),(-1,0),  colors.HexColor(BLUE_DARK)),
            ("TEXTCOLOR",    (0,0),(-1,0),  colors.white),
            ("FONTNAME",     (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTNAME",     (0,1),(-1,-1), "Helvetica"),
            ("FONTSIZE",     (0,0),(-1,-1), 8),
            ("GRID",         (0,0),(-1,-1), 0.5, colors.HexColor(GREY_LINE)),
            ("VALIGN",       (0,0),(-1,-1), "TOP"),
            ("TOPPADDING",   (0,0),(-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ("LEFTPADDING",  (0,0),(-1,-1), 5),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),
             [colors.white, colors.HexColor(BLUE_LIGHT)]),
        ]
        tbl.setStyle(TableStyle(style_cmds))
        elems.append(tbl)
        elems.append(Spacer(1, 0.4*cm))
        return elems

    # ── Recommendations ──────────────────────────────────────────────────────
    def _build_recommendations(self):
        if not REPORTLAB_AVAILABLE:
            return []
        elems = self._section("PRIORITISED RECOMMENDATIONS")
        recs = (self.risk or {}).get("recommendations", [])
        if not recs:
            elems.append(Paragraph("No recommendations available.", self.s_body))
            return elems

        hdr  = [Paragraph(h, self.s_table_hdr)
                for h in ["#","Priority","Recommendation","Action"]]
        rows = [hdr]
        for i, r in enumerate(recs, 1):
            pri = str(r.get("priority","LOW"))
            rows.append([
                Paragraph(str(i),                self.s_table_cell),
                Paragraph(pri,                   self.s_table_cell),
                Paragraph(str(r.get("text","")), self.s_table_cell),
                Paragraph(str(r.get("action","")),self.s_table_cell),
            ])

        tbl = Table(rows, colWidths=[1*cm, 2.5*cm, 8*cm, 5.5*cm])
        style_cmds = [
            ("BACKGROUND",   (0,0),(-1,0),  colors.HexColor(BLUE_DARK)),
            ("TEXTCOLOR",    (0,0),(-1,0),  colors.white),
            ("FONTNAME",     (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTNAME",     (0,1),(-1,-1), "Helvetica"),
            ("FONTSIZE",     (0,0),(-1,-1), 8),
            ("GRID",         (0,0),(-1,-1), 0.5, colors.HexColor(GREY_LINE)),
            ("VALIGN",       (0,0),(-1,-1), "TOP"),
            ("TOPPADDING",   (0,0),(-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ("LEFTPADDING",  (0,0),(-1,-1), 5),
        ]
        for i, r in enumerate(recs, 1):
            pri = r.get("priority","LOW")
            style_cmds.append(("BACKGROUND",(0,i),(-1,i),
                               colors.HexColor(RISK_BG_HEX.get(pri,WHITE))))
        tbl.setStyle(TableStyle(style_cmds))
        elems.append(tbl)
        elems.append(Spacer(1, 0.4*cm))
        return elems

    # ── Footer ───────────────────────────────────────────────────────────────
    def _build_footer(self):
        if not REPORTLAB_AVAILABLE:
            return []
        elems = []
        elems.append(Spacer(1, 0.5*cm))
        elems.append(HRFlowable(width="100%", thickness=1,
                                color=colors.HexColor(BLUE_MED)))
        footer_txt = (
            "CONFIDENTIAL — Generated by AI-Powered Vulnerability Assessment System v11.0  |  "
            "FYP Project  |  For authorized use only"
        )
        elems.append(Paragraph(footer_txt, self.s_footer))
        return elems

    # ── Main generate ────────────────────────────────────────────────────────
    def generate_pdf(self, output_path: str = None) -> str:
        if not REPORTLAB_AVAILABLE:
            logger.error("ReportLab not available.")
            return ""

        if not output_path:
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            docs_path = os.path.join(os.path.expanduser("~"), "Documents")
            os.makedirs(docs_path, exist_ok=True)
            output_path = os.path.join(docs_path, f"vuln_report_{ts}.pdf")

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=1.5*cm, bottomMargin=2*cm,
            title="Vulnerability Assessment Report",
            author="AI Security Suite v11.0",
        )

        story = []
        story += self._build_header()
        story += self._build_metadata()
        story += self._build_risk_summary()
        story += self._build_factors()
        story += self._build_ports()
        story.append(PageBreak())
        story += self._build_recommendations()
        story += self._build_footer()

        try:
            doc.build(story)
            logger.info(f"PDF report generated: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return ""
