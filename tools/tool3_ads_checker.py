import sys
import os
import time
from urllib.parse import urlparse

import pandas as pd
from serpapi import GoogleSearch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import SERPAPI_KEY

print("Running Tool 3 — Ads Checker")

root = os.path.join(os.path.dirname(__file__), "..")
input_file = os.path.join(root, "output", "step2_scored.csv")
df = pd.read_csv(input_file)


def get_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        return domain
    except Exception:
        return None


ads_running_list = []
ads_count_list = []
updated_labels = []

for _, row in df.iterrows():
    website = row.get("website")
    label = row.get("prospect_label")

    ads_running = "UNKNOWN"
    ads_count = 0

    if pd.notna(website):
        domain = get_domain(website)
        if domain:
            try:
                params = {
                    "engine": "google",
                    "q": domain,
                    "api_key": SERPAPI_KEY,
                }
                search = GoogleSearch(params)
                results = search.get_dict()
                ads = results.get("ads", [])
                if ads:
                    ads_running = "YES"
                    ads_count = len(ads)
                else:
                    ads_running = "NO"
                time.sleep(2)
            except Exception as e:
                print(f"Error checking ads for {domain}: {e}")

    new_label = label
    if label == "HOT" and ads_count > 3:
        new_label = "WARM"

    ads_running_list.append(ads_running)
    ads_count_list.append(ads_count)
    updated_labels.append(new_label)

df["ads_running"] = ads_running_list
df["ads_count"] = ads_count_list
df["prospect_label"] = updated_labels

output_file = os.path.join(root, "output", "step3_ads_checked.csv")
df.to_csv(output_file, index=False)

hot_no_ads = int(((df["prospect_label"] == "HOT") & (df["ads_running"] == "NO")).sum())

print("=================================")
print(f"HOT prospects with NO ads: {hot_no_ads}")
print(f"Saved to {output_file}")
print("=================================")
