"""
Digital Guardian - Database models.

Design notes:
  * Timestamps are stored as naive UTC to keep SQLite and PostgreSQL
    behaviour consistent. Serialisation always appends a "Z" suffix so
    clients receive unambiguous ISO-8601 UTC timestamps.
  * Scan rows intentionally store only metadata plus the text the user
    explicitly submitted for analysis. Uploaded images are never written
    to disk or stored in the database.
"""

import json
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db


def utcnow() -> datetime:
    """Return the current time as a naive UTC datetime."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso_utc(value: datetime | None) -> str | None:
    """Serialise a naive-UTC datetime as an ISO-8601 string with 'Z'."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)
    guardian_mode = db.Column(db.Boolean, default=True, nullable=False)
    # Incremented on logout / password change to revoke issued API tokens.
    token_version = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    scans = db.relationship(
        "Scan",
        backref="owner",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    settings = db.relationship(
        "UserSettings",
        backref="user",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def set_password(self, raw_password: str) -> None:
        self.password = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password, raw_password)

    def ensure_settings(self) -> "UserSettings":
        if self.settings is None:
            self.settings = UserSettings()
        return self.settings

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "guardian_mode": bool(self.guardian_mode),
            "created_at": iso_utc(self.created_at),
        }


class UserSettings(db.Model):
    __tablename__ = "user_settings"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False
    )

    notifications_enabled = db.Column(db.Boolean, default=True, nullable=False)
    save_history = db.Column(db.Boolean, default=True, nullable=False)
    # 0 means "keep until the user deletes".
    retention_days = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    def to_dict(self) -> dict:
        return {
            "notifications_enabled": bool(self.notifications_enabled),
            "save_history": bool(self.save_history),
            "retention_days": int(self.retention_days or 0),
        }


class Scan(db.Model):
    __tablename__ = "scan"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False, index=True
    )

    analysis_id = db.Column(db.String(64), index=True)
    # text | url | qr | image | screenshot | message
    input_type = db.Column(db.String(20), default="text", nullable=False)
    channel = db.Column(db.String(50), nullable=False)

    # The submitted text / URL / decoded QR payload. Images are not stored.
    content = db.Column(db.Text, nullable=False)
    url = db.Column(db.Text)

    # QR-specific extracted metadata.
    payload_type = db.Column(db.String(40))
    payload_url = db.Column(db.Text)

    risk_score = db.Column(db.Integer, default=0, index=True)
    rule_score = db.Column(db.Integer, default=0)
    threat_level = db.Column(db.String(50), index=True)
    threat_type = db.Column(db.String(120))
    scam_category = db.Column(db.String(120))

    ml_prediction = db.Column(db.String(20))
    ml_spam_probability = db.Column(db.Float)

    indicators = db.Column(db.JSON, default=list)
    recommendations = db.Column(db.JSON, default=list)
    manipulation = db.Column(db.JSON, default=list)
    evidence = db.Column(db.JSON, default=list)

    explanation = db.Column(db.Text)
    # Retained only when OCR ran successfully and produced text.
    ocr_text = db.Column(db.Text)
    # Backwards-compatible single recommendation string.
    recommendation = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    __table_args__ = (
        db.Index("ix_scan_user_created", "user_id", "created_at"),
    )

    def to_dict(self, include_content: bool = True) -> dict:
        data = {
            "id": self.id,
            "analysis_id": self.analysis_id,
            "input_type": self.input_type,
            "channel": self.channel,
            "url": self.url,
            "payload_type": self.payload_type,
            "payload_url": self.payload_url,
            "risk_score": self.risk_score,
            "rule_score": self.rule_score,
            "threat_level": self.threat_level,
            "threat_type": self.threat_type,
            "scam_category": self.scam_category,
            "ml_prediction": self.ml_prediction,
            "ml_spam_probability": self.ml_spam_probability,
            "indicators": self.indicators or [],
            "recommendations": self.recommendations or [],
            "manipulation": self.manipulation or [],
            "evidence": self.evidence or [],
            "explanation": self.explanation,
            "created_at": iso_utc(self.created_at),
        }
        if include_content:
            data["content"] = self.content
        return data
