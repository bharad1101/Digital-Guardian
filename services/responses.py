"""
Digital Guardian - Unified analysis response builder.

Every analysis path (text, URL, QR, image, screenshot) is normalised into
one documented JSON schema so the website and the mobile app handle
results identically. This module also persists results to the scan history
in a privacy-conscious way (no images, no binary content).
"""

from __future__ import annotations

import uuid

from models import Scan, iso_utc
from services.threat_engine import level_label, score_to_level

MAX_STORED_CONTENT = 10_000


def new_analysis_id() -> str:
    return uuid.uuid4().hex


def build_response(result: dict, *, analysis_id: str, input_type: str,
                   channel: str, content: str, created_at=None) -> dict:
    """Assemble the standard analysis response from an engine result."""
    payload = result.get("payload") if result.get("payload_type") else None
    response = {
        "success": True,
        "analysis_id": analysis_id,
        "input_type": input_type,
        "channel": channel,
        "content": content[:MAX_STORED_CONTENT],
        "risk_score": result.get("risk_score", 0),
        "rule_score": result.get("rule_score", 0),
        "threat_level": result.get("threat_level", "SAFE"),
        "threat_level_label": level_label(result.get("threat_level", "SAFE")),
        "threat_type": result.get("threat_type"),
        "scam_category": result.get("scam_category"),
        "ml_prediction": result.get("ml_prediction", "UNKNOWN"),
        "ml_spam_probability": result.get("ml_spam_probability", 0.0),
        "ml_available": result.get("ml_available", False),
        "indicators": result.get("indicators", []),
        "recommendations": result.get("recommendations", []),
        "manipulation": result.get("manipulation", []),
        "urls": result.get("urls", []),
        "url_reports": result.get("url_reports", []),
        "evidence": result.get("evidence", []),
        "explanation": result.get("explanation"),
        "uncertainty": result.get("uncertainty"),
        "created_at": iso_utc(created_at) if created_at else None,
    }

    # QR-specific block.
    if result.get("payload_type"):
        response["payload"] = {
            "type": result.get("payload_type"),
            "value": payload,
            "url": result.get("payload_url"),
            "url_report": result.get("url_report"),
        }

    # Image-specific block.
    if input_type in ("image", "screenshot") and result.get("sources"):
        response["image"] = {
            "width": result.get("width"),
            "height": result.get("height"),
            "filename": result.get("filename"),
            "sources": result.get("sources"),
            "limitations": result.get("limitations", []),
            "qr_payload": result.get("qr_payload"),
            "ocr_excerpt": (result.get("ocr_text") or "")[:500] or None,
        }

    return response


def persist_scan(user, result: dict, *, analysis_id: str, input_type: str,
                 channel: str, content: str) -> Scan:
    """Create and commit a Scan row for a completed analysis."""
    from extensions import db

    scan = Scan(
        user_id=user.id,
        analysis_id=analysis_id,
        input_type=input_type,
        channel=channel,
        content=(content or "")[:MAX_STORED_CONTENT],
        url=(result.get("payload_url") or (result.get("urls") or [None])[0]),
        payload_type=result.get("payload_type"),
        payload_url=result.get("payload_url"),
        risk_score=result.get("risk_score", 0),
        rule_score=result.get("rule_score", 0),
        threat_level=result.get("threat_level", "SAFE"),
        threat_type=(result.get("threat_type") or "")[:120] or None,
        scam_category=(result.get("scam_category") or "")[:120] or None,
        ml_prediction=result.get("ml_prediction"),
        ml_spam_probability=result.get("ml_spam_probability"),
        indicators=result.get("indicators", []),
        recommendations=result.get("recommendations", []),
        manipulation=result.get("manipulation", []),
        evidence=result.get("evidence", []),
        explanation=result.get("explanation"),
        ocr_text=(result.get("ocr_text") or None),
        recommendation=" ".join(result.get("recommendations", []))[:2000] or None,
    )
    db.session.add(scan)
    db.session.commit()
    return scan


def rebuild_response_from_scan(scan: Scan) -> dict:
    """Reconstruct an API-style response from a stored Scan (for history)."""
    level = scan.threat_level or score_to_level(scan.risk_score or 0)
    data = scan.to_dict()
    data.update({
        "success": True,
        "content": scan.content,
        "threat_level_label": level_label(level),
        "ml_available": scan.ml_prediction not in (None, "UNKNOWN"),
        "uncertainty": (
            "This is a stored analysis result. Website/API output is advisory and "
            "not a guarantee of safety."
        ),
    })
    if scan.payload_type:
        data["payload"] = {
            "type": scan.payload_type,
            "value": scan.content,
            "url": scan.payload_url,
            "url_report": None,
        }
    return data
