import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_CENTER

C_ACCENT    = colors.HexColor("#4a90d9")
C_TEXT      = colors.HexColor("#2c2c2c")
C_TABLE_HDR = colors.HexColor("#1a1f3c")
C_ROW_ALT   = colors.HexColor("#f5f0e8")
C_ROW_NRM   = colors.HexColor("#faf7f2")
C_BORDER    = colors.HexColor("#c8bfa8")
C_RED       = colors.HexColor("#c0392b")

W, H = A4


def make_styles():
    base = getSampleStyleSheet()

    def s(name, parent="Normal", **kw):
        return ParagraphStyle(name, parent=base[parent], **kw)

    return {
        "title":    s("RTitle", "Title", fontSize=22, leading=28,
                      textColor=C_ACCENT, spaceAfter=4, alignment=TA_CENTER),
        "subtitle": s("RSub", fontSize=10, textColor=C_TEXT,
                      alignment=TA_CENTER, spaceAfter=2),
        "h1":       s("RH1", fontSize=14, leading=18, textColor=C_ACCENT,
                      spaceBefore=14, spaceAfter=6, fontName="Helvetica-Bold"),
        "body":     s("RBody", fontSize=9, leading=13, textColor=C_TEXT),
        "tag":      s("RTag", fontSize=8, textColor=C_RED, fontName="Helvetica-Bold"),
        "cell":     s("RCell", fontSize=8, leading=11, textColor=C_TEXT,
                      fontName="Courier", wordWrap="CJK"),
        "cell_hdr": s("RCellH", fontSize=8, leading=11,
                      textColor=colors.white, fontName="Helvetica-Bold"),
    }


def build_table(headers, rows, col_widths, S):
    data = [[Paragraph(h, S["cell_hdr"]) for h in headers]]
    for row in rows:
        data.append([Paragraph(str(c), S["cell"]) for c in row])

    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  C_TABLE_HDR),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_ROW_NRM, C_ROW_ALT]),
        ("GRID",           (0, 0), (-1, -1), 0.4, C_BORDER),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
        ("LEFTPADDING",    (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 5),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
    ]))
    return tbl


def hr(S):
    return HRFlowable(width="100%", thickness=0.5,
                      color=C_BORDER, spaceAfter=6, spaceBefore=2)


def page_header(story, S, ts, target, title, page_num, total):
    story.append(Paragraph("Credential Exposure Report", S["title"]))
    story.append(Paragraph(
        f"Target: {target}  |  {ts}",
        S["subtitle"]))
    story.append(Spacer(1, 0.3*cm))
    story.append(hr(S))
    story.append(Paragraph(f"<b>Section {page_num}/{total} — {title}</b>", S["h1"]))
    story.append(hr(S))
    story.append(Spacer(1, 0.2*cm))


def generate_report(findings: dict, target: str = "N/A", out_path: str = "report.pdf"):
    """
    findings = {
        1: [(source_path, value), ...],
        2: [(source_path, value), ...],
        3: [(source_path, value), ...],
        4: [(source_path, value), ...],
    }
    """
    S   = make_styles()
    ts  = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=1.8*cm,  bottomMargin=1.8*cm,
    )
    story   = []
    FIELDS  = ["Source Path", "Value / Data"]
    WIDTHS  = [7.5*cm, 11.2*cm]

    sections = [
        (1, "Temp File Secrets",
         "Sensitive artefacts from temporary directories — passwords, hashes, connection strings, tokens, keys."),
        (2, "Cache & Config File Secrets",
         "Sensitive data from well-known cache and config files — shadow hashes, SSH configs, DB credentials, cloud keys, WiFi PSKs."),
        (3, "History File Findings",
         "Commands containing credentials or secrets recovered from shell history files."),
        (4, "Browser Credentials",
         "Decrypted credentials extracted from browser profile stores — URLs, usernames, and plaintext passwords."),
    ]

    total = len(sections)

    for idx, (cat, title, desc) in enumerate(sections):
        page_header(story, S, ts, target, title, idx + 1, total)
        story.append(Paragraph(desc, S["body"]))
        story.append(Spacer(1, 0.4*cm))

        rows = findings.get(cat, [])
        if rows:
            story.append(build_table(FIELDS, [[src, val] for src, val in rows], WIDTHS, S))
        else:
            story.append(Paragraph("No findings for this section.", S["tag"]))

        if idx < len(sections) - 1:
            story.append(PageBreak())

    story.append(Spacer(1, 1*cm))
    story.append(hr(S))

    doc.build(story)
    print(f"\n[+] Report saved → {out_path}")
