from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime
import os

# Renkler
RED = HexColor("#f85149")
GREEN = HexColor("#3fb950")
BLUE = HexColor("#58a6ff")
DARK = HexColor("#0d1117")
GRAY = HexColor("#8b949e")
LIGHT_GRAY = HexColor("#161b22")
ORANGE = HexColor("#f0883e")
YELLOW = HexColor("#d29922")

# Font
font_path = "/System/Library/Fonts/Supplemental/Arial Unicode.ttf"
if os.path.exists(font_path):
    pdfmetrics.registerFont(TTFont("Arial", font_path))
    FONT = "Arial"
else:
    FONT = "Helvetica"

def get_score_color(score):
    if score >= 80: return GREEN
    elif score >= 60: return YELLOW
    elif score >= 40: return ORANGE
    else: return RED

def generate_report(domain, scan_data, output_path="cloudaudit_report.pdf"):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle("Title", parent=styles["Normal"], fontSize=22, textColor=BLUE, spaceAfter=6, fontName=FONT)
    subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=11, textColor=GRAY, spaceAfter=20, fontName=FONT)
    section_style = ParagraphStyle("Section", parent=styles["Normal"], fontSize=13, textColor=BLUE, spaceBefore=16, spaceAfter=8, fontName=FONT)
    normal_style = ParagraphStyle("Normal2", parent=styles["Normal"], fontSize=9, textColor=black, spaceAfter=4, fontName=FONT)

    # Başlık
    elements.append(Paragraph("CloudAudit Guvenlik Raporu", title_style))
    elements.append(Paragraph(f"Domain: {domain} — {datetime.now().strftime('%d.%m.%Y %H:%M')}", subtitle_style))

    # Genel skor tablosu
    score = scan_data["score"]
    score_color = get_score_color(score["total_score"])

    summary_data = [
        ["Guvenlik Skoru", "Seviye", "Sorun Sayisi", "Tarih"],
        [str(score["total_score"]) + "/100", f"{score['grade']} - {score['level']}", str(score["issue_count"]), datetime.now().strftime("%d.%m.%Y")]
    ]

    summary_table = Table(summary_data, colWidths=[4*cm, 4*cm, 4*cm, 4*cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), BLUE),
        ("FONTNAME", (0, 0), (-1, -1), FONT),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BACKGROUND", (0, 1), (-1, -1), LIGHT_GRAY),
        ("TEXTCOLOR", (0, 1), (0, 1), score_color),
        ("TEXTCOLOR", (1, 1), (-1, -1), white),
        ("FONTSIZE", (0, 1), (-1, -1), 11),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWHEIGHT", (0, 0), (-1, -1), 0.9*cm),
        ("GRID", (0, 0), (-1, -1), 0.5, GRAY),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.4*cm))

    # Modül skorları
    elements.append(Paragraph("Modul Skorlari", section_style))
    module_data = [
        ["DNS", "SSL", "Portlar", "Cloud", "Email"],
        [
            str(score["scores"]["dns"]),
            str(score["scores"]["ssl"]),
            str(score["scores"]["ports"]),
            str(score["scores"]["cloud"]),
            str(score["scores"]["email"])
        ]
    ]
    module_table = Table(module_data, colWidths=[3.2*cm, 3.2*cm, 3.2*cm, 3.2*cm, 3.2*cm])
    module_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), BLUE),
        ("FONTNAME", (0, 0), (-1, -1), FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BACKGROUND", (0, 1), (-1, -1), LIGHT_GRAY),
        ("TEXTCOLOR", (0, 1), (-1, -1), white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWHEIGHT", (0, 0), (-1, -1), 0.8*cm),
        ("GRID", (0, 0), (-1, -1), 0.5, GRAY),
    ]))
    elements.append(module_table)

    # Sorunlar
    if score["all_issues"]:
        elements.append(Paragraph("Tespit Edilen Sorunlar", section_style))
        for issue in score["all_issues"]:
            elements.append(Paragraph(f"• {issue}", normal_style))

    # DNS
    elements.append(Paragraph("DNS Analizi", section_style))
    dns = scan_data["dns"]
    dns_data = [
        ["A Kayitlari", ", ".join(dns.get("a_records", [])) or "Yok"],
        ["NS Kayitlari", ", ".join(dns.get("ns_records", [])[:2]) or "Yok"],
        ["SPF", "Var" if dns.get("spf") else "Yok"],
        ["DMARC", "Var" if dns.get("dmarc") else "Yok"],
        ["DNSSEC", "Aktif" if dns.get("dnssec") else "Pasif"],
    ]
    dns_table = Table(dns_data, colWidths=[5*cm, 11*cm])
    dns_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (0, -1), LIGHT_GRAY),
        ("TEXTCOLOR", (0, 0), (0, -1), BLUE),
        ("TEXTCOLOR", (1, 0), (1, -1), black),
        ("GRID", (0, 0), (-1, -1), 0.5, GRAY),
        ("ROWHEIGHT", (0, 0), (-1, -1), 0.65*cm),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(dns_table)

    # SSL
    elements.append(Paragraph("SSL Analizi", section_style))
    ssl = scan_data["ssl"]
    ssl_data = [
        ["HTTPS", "Aktif" if ssl.get("has_ssl") else "Yok"],
        ["Yayinci", ssl.get("issuer") or "Bilinmiyor"],
        ["Son Kullanma", ssl.get("expiry_date") or "Bilinmiyor"],
        ["Kalan Gun", str(ssl.get("days_until_expiry")) + " gun" if ssl.get("days_until_expiry") else "Bilinmiyor"],
        ["Versiyon", ssl.get("version") or "Bilinmiyor"],
    ]
    ssl_table = Table(ssl_data, colWidths=[5*cm, 11*cm])
    ssl_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (0, -1), LIGHT_GRAY),
        ("TEXTCOLOR", (0, 0), (0, -1), BLUE),
        ("TEXTCOLOR", (1, 0), (1, -1), black),
        ("GRID", (0, 0), (-1, -1), 0.5, GRAY),
        ("ROWHEIGHT", (0, 0), (-1, -1), 0.65*cm),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(ssl_table)

    # Portlar
    elements.append(Paragraph("Acik Portlar", section_style))
    ports = scan_data["ports"].get("open_ports", [])
    if ports:
        port_data = [["Port", "Servis", "Durum"]]
        for p in ports:
            port_data.append([
                str(p["port"]),
                p["service"],
                "TEHLIKELI" if p["dangerous"] else "Normal"
            ])
        port_table = Table(port_data, colWidths=[3*cm, 8*cm, 5*cm])
        port_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), BLUE),
            ("FONTNAME", (0, 0), (-1, -1), FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BACKGROUND", (0, 1), (-1, -1), white),
            ("TEXTCOLOR", (0, 1), (-1, -1), black),
            ("GRID", (0, 0), (-1, -1), 0.5, GRAY),
            ("ROWHEIGHT", (0, 0), (-1, -1), 0.65*cm),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(port_table)
    else:
        elements.append(Paragraph("Acik port bulunamadi", normal_style))

    # Footer
    elements.append(Spacer(1, 1*cm))
    footer_style = ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=GRAY, alignment=1, fontName=FONT)
    elements.append(Paragraph("CloudAudit — github.com/kaansoyturk/cloudaudit", footer_style))

    doc.build(elements)
    print(f"PDF rapor olusturuldu: {output_path}")
    return output_path