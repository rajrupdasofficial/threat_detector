import os
from datetime import datetime
from urllib.parse import urlparse
from tqdm import tqdm
import logging

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("Warning: reportlab not installed. PDF generation disabled.")
    print("Install with: pip install reportlab")

logger = logging.getLogger(__name__)

def save_pdf_report(result, output_dir):
    """Save result to PDF format"""
    if not PDF_AVAILABLE:
        logger.warning("PDF generation not available. Install reportlab.")
        return None

    print("\nGenerating PDF report...")

    with tqdm(total=5, desc="Generating PDF", unit="section") as pbar:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = urlparse(result['url']).netloc.replace('.', '_').replace(':', '_')
        pdf_filename = os.path.join(output_dir, 'pdf', f'{domain}_{timestamp}.pdf')

        doc = SimpleDocTemplate(pdf_filename, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        pbar.set_description("Creating title section")
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            textColor=colors.darkblue,
            alignment=1  # Center alignment
        )
        story.append(Paragraph("Website Vulnerability Analysis Report", title_style))
        story.append(Spacer(1, 12))
        pbar.update(1)

        pbar.set_description("Creating analysis details")
        # Basic Information (use Paragraph for long texts to enable wrapping)
        story.append(Paragraph("<b>Analysis Details</b>", styles['Heading2']))

        # Define a style for wrapped text
        wrap_style = ParagraphStyle(
            'WrapText',
            parent=styles['Normal'],
            fontSize=10,
            wordWrap='CJK'  # Enables wrapping for long words/phrases
        )

        # Truncate very long texts to prevent overflow (max 200 chars)
        def truncate_text(text, max_len=200):
            return text if len(text) <= max_len else text[:max_len] + "..."

        basic_info = [
            ['URL:', Paragraph(truncate_text(result['url']), wrap_style)],
            ['Analysis Date:', Paragraph(result['analysis_timestamp'], wrap_style)],
            ['Risk Level:', Paragraph(result['risk_level'], wrap_style)],
            ['Predicted Vulnerability:', Paragraph(truncate_text(result['predicted_vulnerability']), wrap_style)],
            ['Confidence Score:', Paragraph(f"{result['confidence']:.2%}", wrap_style)]
        ]

        basic_table = Table(basic_info, colWidths=[2*inch, 4*inch])
        basic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),  # Align text to top for better wrapping
            ('WORDWRAP', (0, 0), (-1, -1), True)  # Enable word wrapping in cells
        ]))

        story.append(basic_table)
        story.append(Spacer(1, 20))
        pbar.update(1)

        pbar.set_description("Creating predictions table")
        # Top Predictions
        story.append(Paragraph("<b>Top 3 Vulnerability Predictions</b>", styles['Heading2']))

        pred_data = [['Rank', 'Vulnerability Type', 'Confidence']]
        for i, (label, conf) in enumerate(result['top_3_predictions'], 1):
            pred_data.append([str(i), Paragraph(truncate_text(label), wrap_style), f"{conf:.2%}"])

        pred_table = Table(pred_data, colWidths=[0.8*inch, 3.5*inch, 1.2*inch])
        pred_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('WORDWRAP', (0, 0), (-1, -1), True)
        ]))

        story.append(pred_table)
        story.append(Spacer(1, 20))
        pbar.update(1)

        pbar.set_description("Creating recommendations")
        # Security Recommendations
        story.append(Paragraph("<b>Security Recommendations</b>", styles['Heading2']))

        for i, rec in enumerate(result['recommendations'], 1):
            story.append(Paragraph(f"{i}. {truncate_text(rec)}", styles['Normal']))
            story.append(Spacer(1, 6))

        story.append(Spacer(1, 20))
        pbar.update(1)

        pbar.set_description("Creating technical details")
        # Technical Details
        story.append(Paragraph("<b>Technical Analysis Details</b>", styles['Heading2']))

        features = result['extracted_features']
        tech_info = [
            ['Technologies Detected:', Paragraph(truncate_text(features.get('technologies', 'None')[:100]), wrap_style)],
            ['Security Headers:', Paragraph('Present' if features.get('security_headers') else 'Missing', wrap_style)],
            ['Forms Detected:', Paragraph('Yes' if features.get('forms') else 'No', wrap_style)],
            ['Suspicious Links:', Paragraph('Found' if features.get('links') else 'None', wrap_style)],
            ['Error Patterns:', Paragraph(truncate_text(features.get('errors', 'None')[:100]), wrap_style)]
        ]

        tech_table = Table(tech_info, colWidths=[2*inch, 4*inch])
        tech_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('WORDWRAP', (0, 0), (-1, -1), True)
        ]))

        story.append(tech_table)

        # Risk Assessment Box
        story.append(Spacer(1, 20))
        risk_color = colors.green if result['risk_level'] == 'LOW' else \
                    colors.orange if result['risk_level'] == 'MEDIUM' else \
                    colors.red if result['risk_level'] == 'HIGH' else colors.darkred

        risk_style = ParagraphStyle(
            'RiskBox',
            parent=styles['Normal'],
            fontSize=12,
            textColor=risk_color,
            alignment=1,
            borderWidth=1,
            borderColor=risk_color
        )

        story.append(Paragraph(f"<b>RISK LEVEL: {result['risk_level']}</b>", risk_style))

        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph("Generated by ML Vulnerability Analysis System",
                              ParagraphStyle('Footer', parent=styles['Normal'],
                                             fontSize=8, textColor=colors.grey, alignment=1)))
        pbar.update(1)

    doc.build(story)
    logger.info(f"PDF report saved: {pdf_filename}")

    return pdf_filename
