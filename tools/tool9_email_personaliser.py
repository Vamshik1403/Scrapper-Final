import sys
import os
import time

import pandas as pd
from openai import OpenAI

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import OPENAI_KEY, YOUR_EMAIL, YOUR_WEBSITE

print("Running Tool 9 — Email Personaliser")

client = OpenAI(api_key=OPENAI_KEY)

root = os.path.join(os.path.dirname(__file__), "..")
input_file = os.path.join(root, "output", "step8_calculated.csv")
df = pd.read_csv(input_file)

results = []

for idx, (_, row) in enumerate(df.iterrows()):
    business = row.get("business_name")
    city = row.get("city")
    reviews = row.get("review_count")
    ads = row.get("ads_running")
    website_quality = row.get("website_quality")
    platform = row.get("platform")

    comp_name = row.get("competitor_1_name")
    comp_reviews = row.get("competitor_1_reviews")

    owner = row.get("owner_name", "there")
    if pd.isna(owner) or owner == "Team":
        owner = "there"
    value_sentence = row.get("value_summary_sentence", "")

    # Build context for AI
    context = f"""
Business: {business} in {city}
Reviews: {reviews}
Ads Running: {ads}
Website: {website_quality} ({platform})
Top Competitor: {comp_name} with {comp_reviews} reviews
Value: {value_sentence}
"""

    opener = ""
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": """You are an expert cold email copywriter.

Write ONE opening line for a cold email.

Rules:
- Max 30 words
- Mention something specific about their business
- Highlight a gap (competitor or missing feature)
- Sound natural and human
- Do NOT sound like AI or marketing""",
                },
                {"role": "user", "content": context},
            ],
        )
        opener = response.choices[0].message.content.strip()
    except Exception as e:
        print(f"  [{idx+1}/{len(df)}] OpenAI error: {e}")
        opener = f"I noticed a few gaps in {business}'s Google presence that could be costing you calls."

    subject = f"Quick question about {business}"

    full_email = f"""Subject: {subject}

Hi {owner},

{opener}

I put together a quick audit showing a few gaps in your Google presence and how you can start getting more calls.

Happy to share it — takes 10 minutes.

Best,
Pravin
{YOUR_WEBSITE}
{YOUR_EMAIL}
"""

    results.append({
        "business_name": business,
        "owner_name": owner,
        "email_subject": subject,
        "custom_opener": opener,
        "full_email": full_email,
    })
    print(f"  [{idx+1}/{len(df)}] {business} — done")
    time.sleep(1)

result_df = pd.DataFrame(results)
output_file = os.path.join(root, "output", "step9_emails.csv")
result_df.to_csv(output_file, index=False)

print("=================================")
print(f"Generated {len(result_df)} personalised emails")
print(f"Saved to {output_file}")
print("=================================")
