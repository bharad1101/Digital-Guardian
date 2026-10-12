"""
Digital Guardian - versioned REST API (/api/v1).

All clients (website JavaScript, mobile app) use these endpoints. Auth is
either a cookie session (website) or a signed Bearer token (mobile).

CSRF: the blueprint is exempt from Flask-WTF's global check so that
token-authenticated mobile clients work, but a before_request hook still
enforces CSRF for cookie-authenticated state-changing requests.
"""

from __future__ import annotations

import base64
import binascii
from functools import wraps
from urllib.parse import urlparse

from flask import Blueprint, current_app, g, jsonify, request
from flask_login import current_user, logout_user
from flask_wtf.csrf import validate_csrf
from wtforms.validators import ValidationError as WTFormsValidationError
from werkzeug.utils import secure_filename

from extensions import csrf, db, limiter
from models import Scan, User
from services import analytics
from services.analysis import analyze
from services.auth_tokens import issue_token, revoke_tokens, verify_token
from services.image_analyzer import (
    ocr_available,
    server_qr_available,
)
from services.ml_service import model_status
from services.validation import (
    ValidationError,
    validate_email,
    validate_name,
    validate_password,
    validate_text,
)

api_bp = Blueprint("api", __name__)
csrf.exempt(api_bp)

LEVELS = ["SAFE", "LOW_RISK", "SUSPICIOUS", "HIGH_RISK", "CRITICAL"]


# --------------------------------------------------------------------- helpers

def json_body() -> dict:
    return request.get_json(silent=True) or {}


def error(message: str, status: int = 400, code: str = "bad_request"):
    return jsonify(success=False, error=message, code=code), status


def current_api_user():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return verify_token(auth[7:].strip())
    if current_user.is_authenticated:
        return current_user
    return None


def api_login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_api_user()
        if user is None:
            return error("Authentication required.", 401, "unauthorized")
        g.api_user = user
        return f(*args, **kwargs)

    return wrapper


@api_bp.before_request
def _enforce_csrf_for_cookie_auth():
    if not current_app.config.get("WTF_CSRF_ENABLED", True):
        return None
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return None  # not cookie-based, CSRF does not apply
    if current_user.is_authenticated:
        try:
            validate_csrf(request.headers.get("X-CSRFToken"))
        except WTFormsValidationError:
            return error("CSRF validation failed.", 400, "csrf_failed")
    return None


def _analysis_config() -> dict:
    from flask import current_app

    return {
        "allowed_exts": current_app.config["ALLOWED_IMAGE_EXTENSIONS"],
        "max_bytes": current_app.config["MAX_CONTENT_LENGTH"],
        "max_dimension": current_app.config["MAX_IMAGE_DIMENSION"],
        "ocr_enabled": current_app.config["OCR_ENABLED"],
        "ocr_lang": current_app.config["OCR_LANG"],
        "ocr_max_chars": current_app.config["OCR_MAX_CHARS"],
    }


# ------------------------------------------------------------------ meta

@api_bp.route("/api/v1/health")
def health():
    return jsonify(success=True, status="ok")


@api_bp.route("/api/v1/capabilities")
def capabilities():
    ml = model_status()
    return jsonify(
        success=True,
        capabilities={
            "ml_model": ml.get("available", False),
            "ml_type": ml.get("type"),
            "ml_classes": ml.get("classes", []),
            "ocr": ocr_available(),
            "server_qr_decode": server_qr_available(),
            "remote_url_inspection": False,
        },
    )


# ------------------------------------------------------------------ auth

@api_bp.route("/api/v1/auth/register", methods=["POST"])
@limiter.limit("10 per hour")
def api_register():
    data = json_body()
    try:
        name = validate_name(data.get("name"))
        email = validate_email(data.get("email"))
        password = validate_password(data.get("password"))
    except ValidationError as exc:
        return error(exc.message, 422, "validation_error")

    if User.query.filter_by(email=email).first():
        return error("An account already exists with this email.", 409, "email_taken")

    user = User(name=name, email=email, guardian_mode=True)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    user.ensure_settings()
    db.session.commit()

    return jsonify(success=True, user=user.to_dict(),
                   token=issue_token(user), settings=user.settings.to_dict()), 201


@api_bp.route("/api/v1/auth/login", methods=["POST"])
@limiter.limit("15 per minute")
def api_login():
    data = json_body()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = User.query.filter_by(email=email).first()
    if user is None or not user.check_password(password):
        return error("Invalid email or password.", 401, "invalid_credentials")

    user.ensure_settings()
    db.session.commit()
    return jsonify(success=True, user=user.to_dict(), token=issue_token(user),
                   settings=user.settings.to_dict())


@api_bp.route("/api/v1/auth/logout", methods=["POST"])
@api_login_required
def api_logout():
    user = g.api_user
    revoke_tokens(user)
    try:
        logout_user()
    except Exception:
        pass
    return jsonify(success=True, message="Logged out.")


@api_bp.route("/api/v1/auth/me")
@api_login_required
def api_me():
    user = g.api_user
    settings = user.ensure_settings()
    db.session.commit()
    return jsonify(success=True, user=user.to_dict(), settings=settings.to_dict())


# ------------------------------------------------------------------ analysis

def _run_analysis(input_type, content, channel, client_qr_payload=None, image_data=None,
                  filename=""):
    user = current_api_user()  # optional auth: analysis works without login
    try:
        result = analyze(
            input_type=input_type,
            content=content,
            channel=channel,
            user=user,
            image_data=image_data,
            filename=filename,
            client_qr_payload=client_qr_payload,
            app_config=_analysis_config(),
        )
    except ValidationError as exc:
        return error(exc.message, 422, "validation_error")
    except Exception:
        from flask import current_app

        current_app.logger.exception("Analysis failed")
        return error("Analysis failed. Please try again.", 500, "analysis_failed")

    if not result.get("success"):
        return error(result.get("error", "Analysis failed."), 422, "analysis_failed")
    return jsonify(result)


@api_bp.route("/api/v1/analyze/text", methods=["POST"])
@limiter.limit("60 per hour")
def api_analyze_text():
    data = json_body()
    try:
        content = validate_text(data.get("text") or data.get("content"),
                                field="Text")
    except ValidationError as exc:
        return error(exc.message, 422, "validation_error")
    channel = (data.get("channel") or "Message")[:50]
    return _run_analysis("text", content, channel)


@api_bp.route("/api/v1/analyze/url", methods=["POST"])
@limiter.limit("60 per hour")
def api_analyze_url():
    data = json_body()
    try:
        content = validate_text(data.get("url"), max_len=2048, field="URL")
    except ValidationError as exc:
        return error(exc.message, 422, "validation_error")

    if "://" not in content:
        content = "http://" + content
    parsed = urlparse(content)
    if not parsed.netloc or "." not in parsed.netloc:
        return error("That does not look like a valid URL.", 422, "validation_error")

    return _run_analysis("url", content, "URL")


@api_bp.route("/api/v1/analyze/qr", methods=["POST"])
@limiter.limit("60 per hour")
def api_analyze_qr():
    data = json_body()
    try:
        content = validate_text(data.get("payload"), field="QR payload")
    except ValidationError as exc:
        return error(exc.message, 422, "validation_error")
    return _run_analysis("qr", content, "QR")


def _read_image_upload() -> tuple[bytes | None, str, str | None, str | None]:
    """Return (data, filename, qr_payload, error)."""
    from flask import current_app

    allowed = current_app.config["ALLOWED_IMAGE_EXTENSIONS"]
    max_bytes = current_app.config["MAX_CONTENT_LENGTH"]

    qr_payload = request.form.get("qr_payload") if request.form else None

    file = request.files.get("image") or request.files.get("file")
    if file is not None:
        filename = secure_filename(file.filename or "upload")
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext and ext not in allowed:
            return None, filename, qr_payload, f"Unsupported image type '.{ext}'."
        data = file.read()
        if len(data) > max_bytes:
            return None, filename, qr_payload, "Image exceeds the upload size limit."
        return data, filename, qr_payload, None

    # Base64 JSON body.
    body = json_body()
    if qr_payload is None and isinstance(body.get("qr_payload"), str):
        qr_payload = body.get("qr_payload")
    b64 = body.get("image_base64") or body.get("image")
    if isinstance(b64, str) and b64:
        if b64.strip().startswith("data:") and "," in b64:
            b64 = b64.split(",", 1)[1]
        try:
            raw = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            return None, "upload", qr_payload, "Image data is not valid base64."
        if len(raw) > max_bytes:
            return None, "upload", qr_payload, "Image exceeds the upload size limit."
        return raw, body.get("filename", "upload"), qr_payload, None

    return None, "", qr_payload, "No image was provided."


def _handle_image(input_type):
    data, filename, qr_payload, err = _read_image_upload()
    if err:
        return error(err, 422, "invalid_image")
    return _run_analysis(input_type, content="[image upload]",
                         channel="Image", client_qr_payload=qr_payload,
                         image_data=data, filename=filename)


@api_bp.route("/api/v1/analyze/image", methods=["POST"])
@limiter.limit("20 per hour")
def api_analyze_image():
    return _handle_image("image")


@api_bp.route("/api/v1/analyze/screenshot", methods=["POST"])
@limiter.limit("20 per hour")
def api_analyze_screenshot():
    return _handle_image("screenshot")


# ------------------------------------------------- legacy QR endpoint (kept)

@api_bp.route("/api/analyze-qr", methods=["POST"])
def legacy_analyze_qr():
    data = json_body()
    payload = data.get("payload")
    if not isinstance(payload, str):
        return error("QR payload must be text.", 400, "invalid_input")
    payload = payload.strip()
    if not payload:
        return error("QR payload is empty.", 400, "invalid_input")
    if len(payload) > 10000:
        return error("QR payload is too large.", 400, "invalid_input")

    result = analyze(input_type="qr", content=payload, channel="QR",
                     user=current_api_user(), app_config=_analysis_config())
    payload_block = result.get("payload", {})
    return jsonify({
        "success": True,
        "qr_analysis": {
            "payload": payload,
            "payload_type": payload_block.get("type"),
            "url": payload_block.get("url"),
            "indicators": result.get("indicators", []),
            "risk_score": result.get("risk_score"),
            "threat_level": result.get("threat_level"),
            "recommendations": result.get("recommendations", []),
        },
        "analysis": result,
    })


# ------------------------------------------------------------------ history

def _paginate_scans(user, *, page, per_page=20):
    query = db.select(Scan).where(Scan.user_id == user.id)

    channel = request.args.get("channel")
    level = request.args.get("level")
    input_type = request.args.get("type") or request.args.get("input_type")
    search = (request.args.get("q") or "").strip()
    sort = request.args.get("sort", "newest")

    if channel:
        query = query.where(Scan.channel == channel)
    if level:
        query = query.where(Scan.threat_level == level)
    if input_type:
        query = query.where(Scan.input_type == input_type)
    if search:
        like = f"%{search}%"
        query = query.where(db.or_(
            Scan.content.ilike(like),
            Scan.threat_type.ilike(like),
            Scan.scam_category.ilike(like),
        ))

    if sort == "oldest":
        query = query.order_by(Scan.created_at.asc())
    elif sort == "risk":
        query = query.order_by(Scan.risk_score.desc(), Scan.created_at.desc())
    else:
        query = query.order_by(Scan.created_at.desc())

    return db.paginate(query, page=max(page, 1), per_page=min(per_page, 100),
                       error_out=False)


@api_bp.route("/api/v1/history")
@api_login_required
def api_history():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    pagination = _paginate_scans(g.api_user, page=page, per_page=per_page)
    return jsonify(
        success=True,
        page=pagination.page,
        per_page=pagination.per_page,
        total=pagination.total,
        pages=pagination.pages,
        items=[s.to_dict(include_content=True) for s in pagination.items],
    )


@api_bp.route("/api/v1/history/<int:scan_id>")
@api_login_required
def api_history_detail(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != g.api_user.id:
        return error("Not found.", 404, "not_found")
    return jsonify(success=True, scan=scan.to_dict())


@api_bp.route("/api/v1/history/<int:scan_id>", methods=["DELETE"])
@api_login_required
@limiter.limit("60 per hour")
def api_history_delete(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != g.api_user.id:
        return error("Not found.", 404, "not_found")
    db.session.delete(scan)
    db.session.commit()
    return jsonify(success=True, message="Deleted.")


@api_bp.route("/api/v1/history", methods=["DELETE"])
@api_login_required
@limiter.limit("10 per hour")
def api_history_delete_all():
    deleted = Scan.query.filter_by(user_id=g.api_user.id).delete(
        synchronize_session=False
    )
    db.session.commit()
    return jsonify(success=True, deleted=deleted)


# ------------------------------------------------------- dashboard / meta

@api_bp.route("/api/v1/dashboard/summary")
@api_login_required
def api_dashboard_summary():
    summary = analytics.dashboard_summary(g.api_user)
    summary["recent"] = [s.to_dict() for s in summary["recent"]]
    return jsonify(success=True, summary=summary)


@api_bp.route("/api/v1/analytics")
@api_login_required
def api_analytics():
    return jsonify(success=True, analytics=analytics.analytics_overview(g.api_user))


@api_bp.route("/api/v1/settings", methods=["GET", "PATCH"])
@api_login_required
def api_settings():
    user = g.api_user
    settings = user.ensure_settings()

    if request.method == "PATCH":
        data = json_body()
        if "name" in data:
            try:
                user.name = validate_name(data.get("name"))
            except ValidationError as exc:
                return error(exc.message, 422, "validation_error")
        if "notifications_enabled" in data:
            settings.notifications_enabled = bool(data["notifications_enabled"])
        if "save_history" in data:
            settings.save_history = bool(data["save_history"])
        if "retention_days" in data:
            try:
                settings.retention_days = max(0, int(data["retention_days"]))
            except (TypeError, ValueError):
                return error("retention_days must be an integer.", 422, "validation_error")
        if "guardian_mode" in data:
            user.guardian_mode = bool(data["guardian_mode"])
        db.session.commit()

    return jsonify(success=True, user=user.to_dict(), settings=settings.to_dict())
