"""
Digital Guardian - API authentication tokens.

Mobile clients authenticate with a signed, time-limited token instead of a
cookie session. Tokens embed the user id and the user's ``token_version``;
incrementing that version (on logout or password change) revokes every
previously issued token for that user.
"""

from __future__ import annotations

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from extensions import db

SALT = "digital-guardian-auth"
DEFAULT_MAX_AGE = 60 * 60 * 24 * 30  # 30 days


def _serializer() -> URLSafeTimedSerializer:
    from flask import current_app

    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=SALT)


def issue_token(user) -> str:
    return _serializer().dumps({"uid": user.id, "v": user.token_version})


def verify_token(token: str, max_age: int = DEFAULT_MAX_AGE):
    """Return the User for a valid token, else None."""
    from models import User

    if not token:
        return None
    try:
        data = _serializer().loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None

    user = db.session.get(User, data.get("uid"))
    if user is None:
        return None
    if data.get("v") != user.token_version:
        return None
    return user


def revoke_tokens(user) -> None:
    user.token_version = (user.token_version or 0) + 1
    db.session.commit()
