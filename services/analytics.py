"""
Digital Guardian - history & analytics aggregation.

All figures are derived from persisted Scan rows for the requesting user.
Nothing is fabricated: an empty database yields empty results.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import func

from extensions import db
from models import Scan
from services.threat_engine import LEVEL_LABELS, normalize_level

LEVEL_ORDER = ["CRITICAL", "HIGH_RISK", "SUSPICIOUS", "LOW_RISK", "SAFE"]


def _user_scans(user_id: int):
    return Scan.query.filter_by(user_id=user_id)


def dashboard_summary(user) -> dict:
    total = _user_scans(user.id).count()

    if total == 0:
        return {
            "total_scans": 0,
            "average_risk": 0,
            "guardian_score": 100,
            "level_counts": {level: 0 for level in LEVEL_ORDER},
            "high_risk_count": 0,
            "most_common_channel": None,
            "most_common_category": None,
            "recent": [],
            "conclusion": (
                "No scans have been analysed yet. Use Guardian Lens or the text "
                "scanner to begin building your personal cybersecurity profile."
            ),
        }

    avg = db.session.query(func.avg(Scan.risk_score)).filter(
        Scan.user_id == user.id
    ).scalar()
    average_risk = int(round(avg or 0))

    rows = db.session.query(Scan.threat_level, func.count(Scan.id)).filter(
        Scan.user_id == user.id
    ).group_by(Scan.threat_level).all()
    level_counts = {level: 0 for level in LEVEL_ORDER}
    for level, count in rows:
        key = normalize_level(level) or "SAFE"
        level_counts[key] = level_counts.get(key, 0) + count
    high_risk_count = level_counts.get("HIGH_RISK", 0) + level_counts.get("CRITICAL", 0)

    channel_rows = db.session.query(Scan.channel, func.count(Scan.id)).filter(
        Scan.user_id == user.id
    ).group_by(Scan.channel).all()
    most_common_channel = (
        max(channel_rows, key=lambda r: r[1])[0] if channel_rows else None
    )

    category_rows = db.session.query(
        Scan.scam_category, func.count(Scan.id)
    ).filter(
        Scan.user_id == user.id,
        Scan.scam_category.isnot(None),
        Scan.scam_category != "None",
    ).group_by(Scan.scam_category).all()
    most_common_category = (
        max(category_rows, key=lambda r: r[1])[0] if category_rows else None
    )

    recent = (
        _user_scans(user.id).order_by(Scan.created_at.desc()).limit(5).all()
    )

    return {
        "total_scans": total,
        "average_risk": average_risk,
        "guardian_score": max(0, 100 - average_risk),
        "level_counts": level_counts,
        "high_risk_count": high_risk_count,
        "most_common_channel": most_common_channel,
        "most_common_category": most_common_category,
        "recent": recent,
        "conclusion": _conclusion(average_risk, total),
    }


def _conclusion(average_risk: int, total: int) -> str:
    if total == 0:
        return "No scans analysed yet."
    if average_risk <= 20:
        return (
            "Your recent scan history shows a low overall threat level. Continue "
            "verifying unexpected links, payment requests and requests for "
            "sensitive information."
        )
    if average_risk <= 50:
        return (
            "Your scan history contains several suspicious items. Exercise caution "
            "with unexpected messages, links, financial requests and unknown senders."
        )
    if average_risk <= 70:
        return (
            "Digital Guardian has detected a significant level of suspicious or "
            "high-risk activity. Avoid interacting with unverified senders and "
            "verify sensitive requests independently."
        )
    return (
        "Your recent scan history contains a high concentration of serious threats. "
        "Do not share OTPs, passwords or banking details, and do not make payments "
        "without independent verification."
    )


def analytics_overview(user) -> dict:
    total = _user_scans(user.id).count()

    avg = db.session.query(func.avg(Scan.risk_score)).filter(
        Scan.user_id == user.id
    ).scalar()
    average_risk = int(round(avg or 0)) if total else 0

    def group(column, exclude_none=False):
        q = db.session.query(column, func.count(Scan.id)).filter(Scan.user_id == user.id)
        if exclude_none:
            q = q.filter(column.isnot(None), column != "None", column != "")
        rows = q.group_by(column).all()
        return {str(name or "Unknown"): count for name, count in rows}

    level_counts = group(Scan.threat_level)
    normalized_levels: dict[str, int] = {}
    for name, count in level_counts.items():
        key = normalize_level(name) or "Unknown"
        normalized_levels[key] = normalized_levels.get(key, 0) + count
    level_counts = {level: normalized_levels[level] for level in LEVEL_ORDER if level in normalized_levels}
    for name, count in normalized_levels.items():
        level_counts.setdefault(name, count)
    channel_counts = group(Scan.channel)
    category_counts = group(Scan.scam_category, exclude_none=True)
    type_counts = group(Scan.input_type)

    # Most risky channel by average score.
    channel_avgs = db.session.query(
        Scan.channel, func.avg(Scan.risk_score)
    ).filter(Scan.user_id == user.id).group_by(Scan.channel).all()
    most_risky_channel = None
    if channel_avgs:
        most_risky_channel = max(channel_avgs, key=lambda r: r[1] or 0)[0]

    # 7-day trend.
    trend = []
    today = datetime.now(timezone.utc).replace(tzinfo=None).date()
    for offset in range(6, -1, -1):
        day = today - timedelta(days=offset)
        start = datetime(day.year, day.month, day.day)
        end = start + timedelta(days=1)
        day_scans = Scan.query.filter(
            Scan.user_id == user.id,
            Scan.created_at >= start,
            Scan.created_at < end,
        ).all()
        trend.append({
            "date": day.isoformat(),
            "count": len(day_scans),
            "average_risk": int(round(sum(s.risk_score or 0 for s in day_scans) / len(day_scans)))
            if day_scans else 0,
        })

    return {
        "total_scans": total,
        "average_risk": average_risk,
        "most_risky_channel": most_risky_channel,
        "level_counts": level_counts,
        "channel_counts": channel_counts,
        "category_counts": category_counts,
        "type_counts": type_counts,
        "trend": trend,
        "level_labels": LEVEL_LABELS,
    }
