import sys
import os
import re
import dns.resolver
import smtplib
import time
from urllib.parse import urljoin, urlparse

import pandas as pd
import requests
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

print("Running Tool 5 — Contact Finder + SMTP Verification")

root = os.path.join(os.path.dirname(__file__), "..")
input_file = os.path.join(root, "output", "HOT_prospects.csv")
df = pd.read_csv(input_file)


def get_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc.replace("www.", "")
    except Exception:
        return None


def find_owner_name(text):
    patterns = [
        r"owner[:\s]+([A-Z][a-z]+ [A-Z][a-z]+)",
        r"founder[:\s]+([A-Z][a-z]+ [A-Z][a-z]+)",
        r"my name is ([A-Z][a-z]+ [A-Z][a-z]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def verify_email_smtp(email):
    """
    Verify an email via SMTP.
    Returns: VALID, INVALID, CATCH-ALL, or UNKNOWN.
    """
    if not email:
        return "UNKNOWN"

    domain = email.split("@")[1]

    # Step 1: Get MX records
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange).rstrip(".")
    except Exception:
        return "NO_MX"

    # Step 2: Connect to SMTP and check
    try:
        smtp = smtplib.SMTP(timeout=10)
        smtp.connect(mx_host, 25)
        smtp.helo("verify.local")
        smtp.mail("test@verify.local")
        code, _ = smtp.rcpt(email)
        # Also test a fake address to detect catch-all
        fake_code, _ = smtp.rcpt(f"zzzfake9999@{domain}")
        smtp.quit()

        if code == 250:
            if fake_code == 250:
                return "CATCH-ALL"
            return "VALID"
        else:
            return "INVALID"
    except smtplib.SMTPServerDisconnected:
        return "UNKNOWN"
    except smtplib.SMTPConnectError:
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


results = []

for idx, (_, row) in enumerate(df.iterrows()):
    website = row.get("website")
    owner_name = "Team"
    email = None
    phone = None
    email_status = "UNKNOWN"

    if pd.notna(website):
        try:
            urls_to_check = [
                website,
                urljoin(website, "/about"),
                urljoin(website, "/about-us"),
            ]
            full_text = ""
            for url in urls_to_check:
                try:
                    r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
                    soup = BeautifulSoup(r.text, "html.parser")
                    full_text += " " + soup.get_text(separator=" ").strip()
                except Exception:
                    continue

            name = find_owner_name(full_text)
            if name:
                owner_name = name

            phone_match = re.search(r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", full_text)
            if phone_match:
                phone = phone_match.group()

            domain = get_domain(website)
            if domain:
                if owner_name != "Team":
                    first = owner_name.split()[0].lower()
                    email = f"{first}@{domain}"
                else:
                    email = f"info@{domain}"

            # Verify the email
            if email:
                print(f"  [{idx+1}/{len(df)}] Verifying {email}...", end=" ")
                email_status = verify_email_smtp(email)
                print(email_status)

        except Exception as e:
            print(f"Error: {website} — {e}")

    results.append({
        "owner_name": owner_name,
        "personal_email": email,
        "email_status": email_status,
        "direct_phone": phone,
    })
    time.sleep(2)

results_df = pd.DataFrame(results)
df = pd.concat([df, results_df], axis=1)

output_file = os.path.join(root, "output", "step5_contacts.csv")
df.to_csv(output_file, index=False)

owner_found = int((df["owner_name"] != "Team").sum())
email_found = int(df["personal_email"].notna().sum())
valid_emails = int((df["email_status"] == "VALID").sum())
catchall = int((df["email_status"] == "CATCH-ALL").sum())
phone_found = int(df["direct_phone"].notna().sum())

print("=================================")
print(f"Owner names found: {owner_found}")
print(f"Emails generated:  {email_found}")
print(f"  VALID:           {valid_emails}")
print(f"  CATCH-ALL:       {catchall}")
print(f"Phones found:      {phone_found}")
print(f"Saved to {output_file}")
print("=================================")
