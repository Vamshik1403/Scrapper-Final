import sys
import os
import time

import pandas as pd
from serpapi import GoogleSearch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import SERPAPI_KEY

print("Running Tool 7 — Competitor Intelligence")

root = os.path.join(os.path.dirname(__file__), "..")
input_file = os.path.join(root, "output", "step6_gbp.csv")
df = pd.read_csv(input_file)

results = []

for idx, (_, row) in enumerate(df.iterrows()):
    city = row.get("city", "")
    review_count = row.get("review_count", 0)
    if pd.isna(review_count):
        review_count = 0
    review_count = int(review_count)

    top1_name, top1_reviews = "", 0
    top2_name, top2_reviews = "", 0
    top3_name, top3_reviews = "", 0
    gap_score = 5  # default mid-range

    if pd.notna(city) and city:
        try:
            params = {
                "engine": "google_maps",
                "q": f"garage door repair {city}",
                "api_key": SERPAPI_KEY,
                "num": 10,
            }
            search = GoogleSearch(params)
            data = search.get_dict()
            competitors = data.get("local_results", [])

            # Sort by reviews descending
            competitors = sorted(
                competitors,
                key=lambda x: int(x.get("reviews", 0) or 0),
                reverse=True,
            )

            # Get top 3
            if len(competitors) >= 1:
                top1_name = competitors[0].get("title", "")
                top1_reviews = int(competitors[0].get("reviews", 0) or 0)
            if len(competitors) >= 2:
                top2_name = competitors[1].get("title", "")
                top2_reviews = int(competitors[1].get("reviews", 0) or 0)
            if len(competitors) >= 3:
                top3_name = competitors[2].get("title", "")
                top3_reviews = int(competitors[2].get("reviews", 0) or 0)

            # Calculate gap score (1-10)
            avg_top3 = (top1_reviews + top2_reviews + top3_reviews) / 3 if (top1_reviews + top2_reviews + top3_reviews) > 0 else 0

            if avg_top3 == 0:
                gap_score = 1
            else:
                ratio = review_count / avg_top3
                if ratio >= 1.0:
                    gap_score = 1  # ahead of competition
                elif ratio >= 0.75:
                    gap_score = 3
                elif ratio >= 0.5:
                    gap_score = 5
                elif ratio >= 0.25:
                    gap_score = 7
                else:
                    gap_score = 9  # far behind

            time.sleep(2)
        except Exception as e:
            print(f"  [{idx+1}/{len(df)}] Error: {e}")

    if gap_score <= 3:
        urgency = "LOW"
    elif gap_score <= 6:
        urgency = "MEDIUM"
    else:
        urgency = "HIGH"

    results.append({
        "top1_name": top1_name,
        "top1_reviews": top1_reviews,
        "top2_name": top2_name,
        "top2_reviews": top2_reviews,
        "top3_name": top3_name,
        "top3_reviews": top3_reviews,
        "competitive_gap_score": gap_score,
        "urgency": urgency,
    })
    print(f"  [{idx+1}/{len(df)}] {row.get('business_name', 'N/A')} → Gap: {gap_score}/10 ({urgency})")

results_df = pd.DataFrame(results)
df = pd.concat([df, results_df], axis=1)

output_file = os.path.join(root, "output", "step7_competitor.csv")
df.to_csv(output_file, index=False)

avg_gap = round(df["competitive_gap_score"].mean(), 1)
low = int((df["urgency"] == "LOW").sum())
medium = int((df["urgency"] == "MEDIUM").sum())
high = int((df["urgency"] == "HIGH").sum())

print("=================================")
print(f"Avg Gap Score: {avg_gap}/10")
print(f"LOW: {low} | MEDIUM: {medium} | HIGH: {high}")
print(f"Saved to {output_file}")
print("=================================")
