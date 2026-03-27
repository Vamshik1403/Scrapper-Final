import os
from dotenv import load_dotenv

load_dotenv()  # reads .env file in project root


def _load_keys(prefix):
    """Load API keys from env. Supports:
    - Single key: PREFIX=key
    - Comma-separated: PREFIX=key1,key2,key3
    - Numbered: PREFIX=key1, PREFIX_2=key2, PREFIX_3=key3
    """
    keys = []
    primary = os.environ.get(prefix, "")
    if primary:
        if "," in primary:
            keys = [k.strip() for k in primary.split(",") if k.strip()]
        else:
            keys.append(primary.strip())
    i = 2
    while True:
        key = os.environ.get(f"{prefix}_{i}", "")
        if not key:
            break
        keys.append(key.strip())
        i += 1
    return keys


SERPAPI_KEYS = _load_keys("SERPAPI_KEY")
OPENAI_KEYS = _load_keys("OPENAI_KEY")

# Backward-compatible single-key exports
SERPAPI_KEY = SERPAPI_KEYS[0] if SERPAPI_KEYS else ""
OPENAI_KEY = OPENAI_KEYS[0] if OPENAI_KEYS else ""

YOUR_EMAIL = os.environ.get("YOUR_EMAIL", "your@email.com")
YOUR_WEBSITE = os.environ.get("YOUR_WEBSITE", "yourwebsite.com")

# SMTP Configuration for outreach email sending
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
