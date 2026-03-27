import sys
import os

import pandas as pd
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

print("Running Tool 10 — PDF Generator")

root = os.path.join(os.path.dirname(__file__), "..")
input_file = os.path.join(root, "output", "step9_emails.csv")
df = pd.read_csv(input_file)

audits_dir = os.path.join(root, "audits")
os.makedirs(audits_dir, exist_ok=True)

styles = getSampleStyleSheet()

for idx, (_, row) in enumerate(df.iterrows()):
    business = row.get("business_name", "Unknown")
    city = row.get("city", "")
    reviews = row.get("review_count", "")
    website_score = row.get("website_score", "")
    gbp_score = row.get("gbp_score", "")
    gap = row.get("competitive_gap_score", "")
    value = row.get("value_summary_sentence", "")

    safe_name = str(business).replace(" ", "_").replace("/", "_")
    filename = os.path.join(audits_dir, f"{safe_name}_Audit.pdf")

    doc = SimpleDocTemplate(filename)
    content = []

    content.append(Paragraph(f"<b>{business} — Audit Report</b>", styles["Title"]))
    content.append(Spacer(1, 20))

    content.append(Paragraph(f"<b>City:</b> {city}", styles["Normal"]))
    content.append(Paragraph(f"<b>Google Reviews:</b> {reviews}", styles["Normal"]))
    content.append(Paragraph(f"<b>Website Score:</b> {website_score}/10", styles["Normal"]))
    content.append(Paragraph(f"<b>GBP Score:</b> {gbp_score}/100", styles["Normal"]))
    content.append(Paragraph(f"<b>Competitive Gap:</b> {gap}/10", styles["Normal"]))

    content.append(Spacer(1, 20))

    content.append(Paragraph("<b>Revenue Opportunity</b>", styles["Heading2"]))
    content.append(Paragraph(str(value) if pd.notna(value) else "Contact us for a detailed analysis.", styles["Normal"]))

    content.append(Spacer(1, 20))

    content.append(Paragraph("<b>Key Issues Found:</b>", styles["Heading2"]))
    content.append(Paragraph("- Low visibility compared to competitors", styles["Normal"]))
    content.append(Paragraph("- Missing or weak Google Ads presence", styles["Normal"]))
    content.append(Paragraph("- Website improvements needed", styles["Normal"]))

    content.append(Spacer(1, 20))

    content.append(Paragraph("<b>Our Solution</b>", styles["Heading2"]))
    content.append(Paragraph(
        "We help garage door companies generate consistent leads using Google Ads and optimisation.",
        styles["Normal"],
    ))

    content.append(Spacer(1, 20))

    content.append(Paragraph("<b>Next Step</b>", styles["Heading2"]))
    content.append(Paragraph(
        "Book a 15-minute call to review this audit and discuss growth opportunities.",
        styles["Normal"],
    ))

    doc.build(content)
    print(f"  [{idx+1}/{len(df)}] {filename}")

print("=================================")
print(f"Generated {len(df)} PDF audits in /audits folder")
print("=================================")
