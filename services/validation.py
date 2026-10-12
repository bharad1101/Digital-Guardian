"""Digital Guardian - input validation helpers."""

from __future__ import annotations

import re

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

MAX_NAME = 100
MAX_EMAIL = 150
MIN_PASSWORD = 8
MAX_PASSWORD = 200
MAX_TEXT = 10_000
MAX_URL = 2_048
MAX_QR = 10_000


class ValidationError(Exception):
    def __init__(self, message: str, field: str | None = None):
        super().__init__(message)
        self.message = message
        self.field = field


def clean_str(value, *, max_len: int, field: str, required: bool = True) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be text.", field)
    value = value.strip()
    if required and not value:
        raise ValidationError(f"{field} is required.", field)
    if len(value) > max_len:
        raise ValidationError(
            f"{field} must be {max_len} characters or fewer.", field
        )
    return value


def validate_email(value) -> str:
    email = clean_str(value, max_len=MAX_EMAIL, field="Email").lower()
    if not EMAIL_RE.match(email):
        raise ValidationError("Please enter a valid email address.", "email")
    return email


def validate_name(value) -> str:
    return clean_str(value, max_len=MAX_NAME, field="Name")


def validate_password(value) -> str:
    if not isinstance(value, str):
        raise ValidationError("Password must be text.", "password")
    if len(value) < MIN_PASSWORD:
        raise ValidationError(
            f"Password must be at least {MIN_PASSWORD} characters.", "password"
        )
    if len(value) > MAX_PASSWORD:
        raise ValidationError("Password is too long.", "password")
    return value


def validate_text(value, *, max_len: int = MAX_TEXT, field: str = "Content") -> str:
    return clean_str(value, max_len=max_len, field=field)
