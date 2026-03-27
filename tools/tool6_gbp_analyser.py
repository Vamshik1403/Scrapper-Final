import sys
import os
import time

import pandas as pd
from serpapi import GoogleSearch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import SERPAPI_KEY

print("Running Tool 6 — GBP Analyser")

root = os.path.join(os.path.dirname(__file__), "..")
input_file = os.path.join(root, "output", "step5_contacts.csv")
df = pd.read_csv(input_file)

results = []

for idx, (_, row) in enumerate(df.iterrows()):
    place_id = row.get("place_id")

    gbp_score = 0
    photos = 0
    services = 0
    has_description = False
    has_hours = False
    has_posts = False
    review_reply_rate = 0.0

    if pd.notna(place_id):
        try:
            params = {
                "engine": "google_maps",
                "place_id": place_id,
                "api_key": SERPAPI_KEY,
            }
            search = GoogleSearch(params)
            data = search.get_dict()

            # Photos
            photos = len(data.get("photos", []))
            if photos > 20:
                gbp_score += 20
            elif photos >= 10:
                gbp_score += 10
            elif photos > 0:
                gbp_score += 5

            # Description
            desc = data.get("description", "")
            if desc:
                has_description = True
                gbp_score += 15 if len(desc) > 150 else 8

            # Services
            services_list = data.get("services", [])
            services = len(services_list)
            if services > 5:
                gbp_score += 15
            elif services >= 2:
                gbp_score += 8

            # Review replies
            reviews = data.get("reviews", [])
            responses = sum(1 for r in reviews if "response" in r)
            if len(reviews) > 0:
                review_reply_rate = round(responses / len(reviews), 2)
                if review_reply_rate > 0.5:
                    gbp_score += 15
                elif review_reply_rate > 0:
                    gbp_score += 8

            # Business hours
            hours = data.get("hours", {})
            if hours:
                has_hours = True
                gbp_score += 15

            # Recent posts
            posts = data.get("posts", [])
            if posts:
                has_posts = True
                gbp_score += 20

            time.sleep(2)
        except Exception as e:
            print(f"  [{idx+1}/{len(df)}] Error fetching GBP: {e}")

    if gbp_score < 40:
        label = "POOR"
    elif gbp_score <= 70:
        label = "AVERAGE"
    else:
        label = "STRONG"

    results.append({
        "gbp_photos": photos,
        "gbp_services": services,
        "gbp_has_description": has_description,
        "gbp_has_hours": has_hours,
        "gbp_has_posts": has_posts,
        "gbp_reply_rate": review_reply_rate,
        "gbp_score": gbp_score,
        "gbp_label": label,
    })
    print(f"  [{idx+1}/{len(df)}] {row.get('business_name', 'N/A')} → {gbp_score}/100 ({label})")

results_df = pd.DataFrame(results)
df = pd.concat([df, results_df], axis=1)

output_file = os.path.join(root, "output", "step6_gbp.csv")
df.to_csv(output_file, index=False)

avg = round(df["gbp_score"].mean(), 1)
poor = int((df["gbp_label"] == "POOR").sum())
avg_count = int((df["gbp_label"] == "AVERAGE").sum())
strong = int((df["gbp_label"] == "STRONG").sum())

print("=================================")
print(f"Avg GBP Score: {avg}/100")
print(f"POOR: {poor} | AVERAGE: {avg_count} | STRONG: {strong}")
print(f"Saved to {output_file}")
print("=================================")
