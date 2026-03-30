# gunicorn.conf.py — Production config for GarageLeadsPro
# Usage: gunicorn -c gunicorn.conf.py app:app

import os

# Bind
bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"

# Workers — MUST be 1 because background threads (pipeline, outreach)
# store status in in-memory dicts. Multiple workers = separate memory = lost status.
# Use threads to handle concurrent requests instead.
workers = 1
threads = 4

# Timeout (long for tool runs)
timeout = 300

# Security
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Preload for faster restarts
preload_app = True
