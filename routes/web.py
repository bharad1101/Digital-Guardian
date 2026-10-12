"""Digital Guardian - website page routes."""

from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required

from extensions import db
from models import Scan
from services import analytics
from services.analysis import analyze
from services.validation import ValidationError, validate_text
from services.threat_engine import LEVEL_LABELS

web_bp = Blueprint("web", __name__)

PER_PAGE = 20


@web_bp.route("/")
def home():
    return render_template("index.html")


@web_bp.route("/dashboard")
@login_required
def dashboard():
    summary = analytics.dashboard_summary(current_user)
    return render_template("dashboard.html", **summary)


@web_bp.route("/guardian-mode", methods=["POST"])
@login_required
def guardian_mode():
    current_user.guardian_mode = not current_user.guardian_mode
    db.session.commit()
    if current_user.guardian_mode:
        flash("Guardian Mode activated.", "success")
    else:
        flash("Guardian Mode paused.", "warning")
    return redirect(url_for("web.dashboard"))


@web_bp.route("/scan", methods=["GET", "POST"])
@web_bp.route("/scanner", methods=["GET", "POST"])
@login_required
def scanner():
    result = None
    submitted_content = ""
    selected_channel = "Message"

    if request.method == "POST":
        selected_channel = request.form.get("channel", "Message")
        try:
            submitted_content = validate_text(
                request.form.get("content"), field="Content"
            )
        except ValidationError as exc:
            flash(exc.message, "warning")
            return redirect(url_for("web.scanner"))

        result = analyze(
            input_type="text",
            content=submitted_content,
            channel=selected_channel,
            user=current_user,
            app_config=_analysis_config(),
        )

    return render_template(
        "scanner.html",
        result=result,
        submitted_content=submitted_content,
        selected_channel=selected_channel,
        level_labels=LEVEL_LABELS,
    )


@web_bp.route("/lens")
@web_bp.route("/qr-scanner")
@login_required
def lens():
    return render_template("lens.html")


@web_bp.route("/image")
@login_required
def image_scanner():
    return render_template("image_scanner.html")


@web_bp.route("/history")
@login_required
def history():
    query = db.select(Scan).where(Scan.user_id == current_user.id)

    channel = request.args.get("channel", "")
    level = request.args.get("level", "")
    input_type = request.args.get("type", "")
    search = (request.args.get("q", "") or "").strip()
    sort = request.args.get("sort", "newest")

    if channel:
        query = query.where(Scan.channel == channel)
    if level:
        normalized = level.strip().replace(" ", "_").upper()
        query = query.where(
            Scan.threat_level.in_([normalized, normalized.replace("_", " ")])
        )
    if input_type:
        query = query.where(Scan.input_type == input_type)
    if search:
        like = f"%{search}%"
        query = query.where(
            db.or_(
                Scan.content.ilike(like),
                Scan.threat_type.ilike(like),
                Scan.scam_category.ilike(like),
            )
        )

    if sort == "oldest":
        query = query.order_by(Scan.created_at.asc())
    elif sort == "risk":
        query = query.order_by(Scan.risk_score.desc(), Scan.created_at.desc())
    else:
        query = query.order_by(Scan.created_at.desc())

    page = request.args.get("page", 1, type=int)
    pagination = db.paginate(query, page=max(page, 1), per_page=PER_PAGE,
                             error_out=False)

    return render_template(
        "history.html",
        scans=pagination.items,
        pagination=pagination,
        channel_filter=channel,
        level_filter=level,
        type_filter=input_type,
        search=search,
        sort=sort,
        level_labels=LEVEL_LABELS,
    )


@web_bp.route("/history/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != current_user.id:
        abort(404)
    db.session.delete(scan)
    db.session.commit()
    flash("Scan removed from history.", "success")
    return redirect(request.referrer or url_for("web.history"))


@web_bp.route("/history/delete-all", methods=["POST"])
@login_required
def delete_all_scans():
    Scan.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)
    db.session.commit()
    flash("All scan history deleted.", "success")
    return redirect(url_for("web.history"))


@web_bp.route("/result/<int:scan_id>")
@login_required
def result_detail(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != current_user.id:
        abort(404)
    from services.responses import rebuild_response_from_scan

    return render_template("result.html", scan=rebuild_response_from_scan(scan),
                           scan_id=scan.id, level_labels=LEVEL_LABELS)


@web_bp.route("/analytics")
@login_required
def analytics_page():
    overview = analytics.analytics_overview(current_user)
    return render_template("analytics.html", **overview)


@web_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user_settings = current_user.ensure_settings()

    if request.method == "POST":
        action = request.form.get("action", "save")

        if action == "save":
            name = (request.form.get("name") or "").strip()
            if name:
                current_user.name = name[:100]
            user_settings.notifications_enabled = "notifications_enabled" in request.form
            user_settings.save_history = "save_history" in request.form
            try:
                retention = int(request.form.get("retention_days", "0"))
            except (TypeError, ValueError):
                retention = 0
            user_settings.retention_days = max(0, retention)
            db.session.commit()
            flash("Settings saved.", "success")

        elif action == "delete_history":
            Scan.query.filter_by(user_id=current_user.id).delete(
                synchronize_session=False
            )
            db.session.commit()
            flash("All scan history deleted.", "success")

        return redirect(url_for("web.settings"))

    return render_template("settings.html", user_settings=user_settings)


@web_bp.route("/privacy")
def privacy():
    return render_template("privacy.html")


def _analysis_config() -> dict:
    return {
        "allowed_exts": current_app_allowed_exts(),
        "max_bytes": _cfg("MAX_CONTENT_LENGTH", 8 * 1024 * 1024),
        "max_dimension": _cfg("MAX_IMAGE_DIMENSION", 8000),
        "ocr_enabled": _cfg("OCR_ENABLED", True),
        "ocr_lang": _cfg("OCR_LANG", "eng"),
        "ocr_max_chars": _cfg("OCR_MAX_CHARS", 4000),
    }


def _cfg(key, default):
    from flask import current_app

    return current_app.config.get(key, default)


def current_app_allowed_exts():
    return _cfg("ALLOWED_IMAGE_EXTENSIONS", {"png", "jpg", "jpeg", "webp"})
