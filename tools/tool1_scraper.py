import sys
import os
import time

import pandas as pd
from serpapi import GoogleSearch
from tqdm import tqdm

# Allow imports from the project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import SERPAPI_KEY


def load_cities(filepath="cities.txt"):
    """Load city list from a text file (one city per line)."""
    root = os.path.join(os.path.dirname(__file__), "..")
    with open(os.path.join(root, filepath)) as f:
        return [line.strip() for line in f if line.strip()]


def scrape_city(city, query_template="garage door repair {city}"):
    """Search Google Maps for businesses in a given city and return a list of result dicts."""
    params = {
        "engine": "google_maps",
        "q": query_template.format(city=city),
        "api_key": SERPAPI_KEY,
    }

    search = GoogleSearch(params)
    results = search.get_dict()

    businesses = results.get("local_results", [])
    rows = []
    for b in businesses:
        rows.append({
            "business_name": b.get("title"),
            "phone": b.get("phone"),
            "website": b.get("website"),
            "address": b.get("address"),
            "rating": b.get("rating"),
            "review_count": b.get("reviews"),
            "place_id": b.get("place_id"),
            "city": city,
        })
    return rows


def main():
    cities = load_cities()
    all_results = []

    for city in tqdm(cities, desc="Scraping cities"):
        rows = scrape_city(city)
        all_results.extend(rows)
        # Pause between requests to avoid rate-limiting
        time.sleep(3)

    df = pd.DataFrame(all_results)

    output_dir = os.path.join(os.path.dirname(__file__), "..", "output")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "step1_raw.csv")

    df.to_csv(output_path, index=False)
    print(f"Done. Found {len(df)} companies. Saved to {output_path}")


if __name__ == "__main__":
    main()
