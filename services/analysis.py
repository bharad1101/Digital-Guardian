"""
Digital Guardian - analysis orchestration.

Single entry point that every client (website, mobile app, legacy API)
uses to run an analysis, build the standard response and persist it to
history when the user has history saving enabled.
"""

from __future__ import annotations

from services import image_analyzer, qr_analyzer, threat_engine
from services.responses import (
    build_response,
    new_analysis_id,
    persist_scan,
)

ALLOWED_INPUT_TYPES = {"text", "url", "qr", "image", "screenshot"}


def _maybe_persist(user, result, *, analysis_id, input_type, channel, content):
    if user is None:
        return None
    try:
        settings = user.ensure_settings()
    except Exception:
        settings = None
    if settings is not None and not settings.save_history:
        return None
    try:
        return persist_scan(
            user, result, analysis_id=analysis_id,
            input_type=input_type, channel=channel, content=content,
        )
    except Exception:
        # Persistence must never break analysis delivery.
        from extensions import db
        import logging

        logging.getLogger(__name__).exception("Failed to persist scan")
        db.session.rollback()
        return None


def analyze(*, input_type: str, content: str, channel: str = "Message",
            user=None, image_data: bytes | None = None,
            filename: str = "", client_qr_payload: str | None = None,
            app_config: dict | None = None) -> dict:
    """Run an analysis and return the standard response dict."""
    cfg = app_config or {}
    analysis_id = new_analysis_id()

    if input_type == "text":
        engine_result = threat_engine.analyze_threat(content, channel or "Message")
    elif input_type == "url":
        engine_result = threat_engine.analyze_threat(content, channel="URL")
    elif input_type == "qr":
        engine_result = qr_analyzer.analyze_qr(content)
    elif input_type in ("image", "screenshot"):
        outcome = image_analyzer.analyze_image(
            image_data or b"",
            filename=filename,
            allowed_exts=cfg.get("allowed_exts"),
            max_bytes=cfg.get("max_bytes", 8 * 1024 * 1024),
            max_dimension=cfg.get("max_dimension", 8000),
            client_qr_payload=client_qr_payload,
            ocr_enabled=cfg.get("ocr_enabled", True),
            ocr_lang=cfg.get("ocr_lang", "eng"),
            ocr_max_chars=cfg.get("ocr_max_chars", 4000),
        )
        if not outcome.get("success"):
            return {
                "success": False,
                "analysis_id": analysis_id,
                "input_type": input_type,
                "error": outcome.get("error", "Could not analyse image."),
            }
        engine_result = outcome["result"]
        channel = "Image"
    else:
        return {
            "success": False,
            "analysis_id": analysis_id,
            "input_type": input_type,
            "error": f"Unsupported input type: {input_type}",
        }

    response = build_response(
        engine_result,
        analysis_id=analysis_id,
        input_type=input_type,
        channel=channel,
        content=content,
    )
    scan = _maybe_persist(
        user, engine_result, analysis_id=analysis_id,
        input_type=input_type, channel=channel, content=content,
    )
    if scan is not None:
        from models import iso_utc

        response["created_at"] = iso_utc(scan.created_at)
        response["saved"] = True
        response["scan_id"] = scan.id
    else:
        response["saved"] = False
    return response
