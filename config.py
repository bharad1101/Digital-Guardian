
"""
Digital Guardian - Application configuration.

All sensitive values are read from environment variables. Development
defaults are provided so the application can run locally without a
configuration file, but those defaults are intentionally NOT suitable
for production (the app refuses to start in production without a real
SECRET_KEY).
"""

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# Load a local .env file if present (never committed to source control).
load_dotenv(BASE_DIR / ".env")


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    """Base configuration shared by every environment."""

    # -- Core ---------------------------------------------------------
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-insecure-secret-change-me")
    ENV = os.getenv("FLASK_ENV", "development")

    # -- Database -----------------------------------------------------
    # SQLite is the local default; hosted deployments can use Aiven MySQL.
    _database_url = os.getenv(
        "DATABASE_URL",
        "sqlite:///" + str(BASE_DIR / "instance" / "digital_guardian.db"),
    )

    # SQLAlchemy defaults to MySQLdb for mysql:// URLs.
    # Explicitly select PyMySQL, which is installed through requirements.txt.
    if _database_url.startswith("mysql://"):
        _database_url = _database_url.replace(
            "mysql://", "mysql+pymysql://", 1
        )

    # Remove Aiven's URL query options because SSL is configured below.
    if _database_url.startswith("mysql+pymysql://"):
        _database_url = _database_url.split("?", 1)[0]

    SQLALCHEMY_DATABASE_URI = _database_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # Aiven requires an encrypted connection.
    # Uses the system's trusted CA certificates and checks the server hostname.
    if _database_url.startswith("mysql+pymysql://"):
        SQLALCHEMY_ENGINE_OPTIONS["connect_args"] = {
            "ssl": {"check_hostname": True}
        }

    # -- Sessions / cookies ------------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = _bool_env("SESSION_COOKIE_SECURE", False)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = _bool_env("REMEMBER_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = int(
        os.getenv("SESSION_LIFETIME_SECONDS", 60 * 60 * 12)
    )

    # -- CSRF ---------------------------------------------------------
    WTF_CSRF_ENABLED = _bool_env("WTF_CSRF_ENABLED", True)
    WTF_CSRF_TIME_LIMIT = int(
        os.getenv("WTF_CSRF_TIME_LIMIT", 60 * 60 * 4)
    )

    # -- Uploads ------------------------------------------------------
    MAX_CONTENT_LENGTH = int(
        os.getenv("MAX_CONTENT_LENGTH", 8 * 1024 * 1024)
    )
    ALLOWED_IMAGE_EXTENSIONS = {
        "png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff"
    }
    MAX_IMAGE_DIMENSION = int(os.getenv("MAX_IMAGE_DIMENSION", 8000))

    # -- Rate limiting ------------------------------------------------
    RATELIMIT_STORAGE_URI = os.getenv(
        "RATELIMIT_STORAGE_URI", "memory://"
    )
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "300 per hour")
    RATELIMIT_HEADERS_ENABLED = True

    # -- Analysis engine ----------------------------------------------
    ML_MODEL_PATH = os.getenv(
        "ML_MODEL_PATH", str(BASE_DIR / "ml" / "spam_model.pkl")
    )
    # OCR is only attempted when the Tesseract binary is available.
    OCR_ENABLED = _bool_env("OCR_ENABLED", True)
    OCR_LANG = os.getenv("OCR_LANG", "eng")
    OCR_MAX_CHARS = int(os.getenv("OCR_MAX_CHARS", 4000))

    # Remote URL inspection is disabled unless explicitly enabled.
    ENABLE_REMOTE_URL_INSPECTION = _bool_env(
        "ENABLE_REMOTE_URL_INSPECTION", False
    )
    REMOTE_URL_TIMEOUT = int(os.getenv("REMOTE_URL_TIMEOUT", 5))
    REMOTE_URL_MAX_BYTES = int(
        os.getenv("REMOTE_URL_MAX_BYTES", 512 * 1024)
    )

    # -- Privacy ------------------------------------------------------
    # Retention in days for scan history (0 = keep until user deletes).
    DEFAULT_RETENTION_DAYS = int(os.getenv("DEFAULT_RETENTION_DAYS", 0))


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "testing-secret-key"


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = "https"

    @classmethod
    def validate(cls):
        if not os.getenv("SECRET_KEY"):
            raise RuntimeError(
                "SECRET_KEY must be set in production "
                "(refusing insecure default)."
            )


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(name: str | None = None):
    env = (name or os.getenv("FLASK_ENV", "development")).lower()
    return CONFIG_MAP.get(env, DevelopmentConfig)
