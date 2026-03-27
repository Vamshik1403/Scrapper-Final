import sys
import os
import time
import re

import pandas as pd
import requests
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

print("Running Tool 4 — Website Checker")

root = os.path.join(os.path.dirname(__file__), "..")
input_file = os.path.join(root, "output", "step3_ads_checked.csv")
df = pd.read_csv(input_file)

results = []

for _, row in df.iterrows():
    url = row.get("website")

    score = 0
    load_speed = None
    has_mobile = False
    has_phone = False
    has_form = False
    has_https = False
    copyright_year = None
    has_booking = False
    platform = "UNKNOWN"

    if pd.notna(url):
        try:
            start = time.time()
            response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            load_speed = round(time.time() - start, 2)

            html = response.text.lower()

            # HTTPS
            if url.startswith("https"):
                has_https = True
                score += 1

            # Speed
            if load_speed and load_speed < 3:
                score += 2

            # Mobile
            if 'meta name="viewport"' in html or "meta name='viewport'" in html:
                has_mobile = True
                score += 2

            # Clickable phone
            if "tel:" in html:
                has_phone = True
                score += 2

            # Contact form
            if "<form" in html:
                has_form = True
                score += 1

            # Booking
            if any(word in html for word in ["book", "schedule", "appointment"]):
                has_booking = True
                score += 1

            # Copyright year
            years = re.findall(r"20[0-9]{2}", html)
            if years:
                copyright_year = max(years)
                if int(copyright_year) >= 2023:
                    score += 1

            # Platform detection
            if "wix" in html:
                platform = "WIX"
            elif "wordpress" in html or "wp-content" in html:
                platform = "WORDPRESS"
            elif "squarespace" in html:
                platform = "SQUARESPACE"
            elif "godaddy" in html:
                platform = "GODADDY"
            else:
                platform = "CUSTOM"

        except Exception as e:
            print(f"Error loading: {url} — {e}")
    else:
        platform = "NO WEBSITE"

    if score <= 3:
        quality = "BAD"
    elif score <= 6:
        quality = "BASIC"
    else:
        quality = "GOOD"

    results.append({
        "load_speed": load_speed,
        "has_mobile": has_mobile,
        "has_phone": has_phone,
        "has_form": has_form,
        "has_https": has_https,
        "copyright_year": copyright_year,
        "has_booking": has_booking,
        "platform": platform,
        "website_score": score,
        "website_quality": quality,
    })

    time.sleep(2)

# Merge results
results_df = pd.DataFrame(results)
df = pd.concat([df, results_df], axis=1)

output_dir = os.path.join(root, "output")
df.to_csv(os.path.join(output_dir, "step4_website_checked.csv"), index=False)

# Filter by prospect label
hot_df = df[df["prospect_label"] == "HOT"]
warm_df = df[df["prospect_label"] == "WARM"]

hot_df.to_csv(os.path.join(output_dir, "HOT_prospects.csv"), index=False)
warm_df.to_csv(os.path.join(output_dir, "WARM_prospects.csv"), index=False)

print("=================================")
print("PIPELINE FILTER APPLIED")
print(f"HOT prospects: {len(hot_df)}")
print(f"WARM prospects: {len(warm_df)}")
print(f"COLD removed: {len(df) - len(hot_df) - len(warm_df)}")
print("=================================")
