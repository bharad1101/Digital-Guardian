"""
WSGI entry point for Digital Guardian.

Usage (development):
    flask --app wsgi run --debug

Usage (production, gunicorn):
    gunicorn --workers 4 --bind 0.0.0.0:8000 wsgi:app

The application is created by the factory in app.py using configuration
selected from the FLASK_ENV environment variable (default: development).
"""

import os

from app import create_app

# Fail fast in production if required secrets are missing.
if os.getenv("FLASK_ENV", "development").lower() == "production":
    from config import ProductionConfig

    ProductionConfig.validate()

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")))
