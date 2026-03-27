import os
import pandas as pd

print("Running Tool 2 — Review Scorer")

# Resolve paths relative to project root
root = os.path.join(os.path.dirname(__file__), "..")

# Load data from Tool 1
input_file = os.path.join(root, "output", "step1_raw.csv")
df = pd.read_csv(input_file)


def score_reviews(review_count):
    """Classify a business as HOT/WARM/COLD based on review count."""
    if pd.isna(review_count):
        return 3, "HOT"

    review_count = int(review_count)

    if review_count <= 79:
        return 3, "HOT"
    elif review_count <= 150:
        return 2, "WARM"
    else:
        return 1, "COLD"


# Apply scoring
scores = df["review_count"].apply(score_reviews)
df["review_score"] = scores.apply(lambda x: x[0])
df["prospect_label"] = scores.apply(lambda x: x[1])

# Save result
output_file = os.path.join(root, "output", "step2_scored.csv")
df.to_csv(output_file, index=False)

# Summary
hot = (df["prospect_label"] == "HOT").sum()
warm = (df["prospect_label"] == "WARM").sum()
cold = (df["prospect_label"] == "COLD").sum()

print("=================================")
print(f"HOT: {hot} | WARM: {warm} | COLD: {cold} | Total: {len(df)}")
print(f"Saved to {output_file}")
print("=================================")
