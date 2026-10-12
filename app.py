"""
Digital Guardian - application factory.

Creates the Flask app, wires up extensions, blueprints, security headers,
error handlers, template helpers and CLI commands.

Run the development server:
    venv/bin/flask --app app run --debug

Run in production (example):
    venv/bin/gunicorn "app:create_app('production')" -b 0.0.0.0:8000
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import click
from flask import Flask, jsonify, render_template, request

from config import ProductionConfig, get_config
from extensions import csrf, db, limiter, login_manager, migrate


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=False)

    config_class = get_config(config_name)
    app.config.from_object(config_class)

    if config_class is ProductionConfig:
        ProductionConfig.validate()

    _configure_logging(app)
    _init_extensions(app)
    _register_blueprints(app)
    _register_template_helpers(app)
    _register_error_handlers(app)
    _register_security_headers(app)
    _register_cli(app)
    _register_user_loader()

    return app


def _configure_logging(app: Flask) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _init_extensions(app: Flask) -> None:
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)


def _register_user_loader() -> None:
    from models import User

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None


def _register_blueprints(app: Flask) -> None:
    from routes.api import api_bp
    from routes.auth import auth_bp
    from routes.web import web_bp

    app.register_blueprint(web_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)


def _register_template_helpers(app: Flask) -> None:
    from services.threat_engine import level_label as _level_label_fn, normalize_level

    @app.template_filter("dt")
    def _format_dt(value):
        if not value:
            return "-"
        if isinstance(value, str):
            return value
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M UTC")

    @app.template_filter("level_label")
    def _level_label(value):
        return _level_label_fn(value)

    @app.template_filter("level_class")
    def _level_class(value):
        return {
            "SAFE": "lvl-safe",
            "LOW_RISK": "lvl-low",
            "SUSPICIOUS": "lvl-suspicious",
            "HIGH_RISK": "lvl-high",
            "CRITICAL": "lvl-critical",
        }.get(normalize_level(value), "lvl-unknown")

    @app.template_filter("risk_color")
    def _risk_color(value):
        return {
            "SAFE": "#22c55e",
            "LOW_RISK": "#84cc16",
            "SUSPICIOUS": "#f59e0b",
            "HIGH_RISK": "#f97316",
            "CRITICAL": "#ef4444",
        }.get(value, "#38bdf8")

    @app.context_processor
    def _inject_globals():
        from services.image_analyzer import ocr_available
        from services.ml_service import model_status

        def capabilities():
            try:
                ml = model_status()
                return {"ml": ml.get("available", False), "ocr": ocr_available()}
            except Exception:
                return {"ml": False, "ocr": False}

        return {
            "app_version": "1.0.0",
            "now_year": datetime.now(timezone.utc).year,
            "capabilities": capabilities,
        }


def _register_error_handlers(app: Flask) -> None:
    def _wants_json() -> bool:
        return request.path.startswith("/api/") or (
            request.accept_mimetypes.best == "application/json"
        )

    @app.errorhandler(400)
    def _bad_request(error):
        if _wants_json():
            return jsonify(success=False, error="Bad request", code="bad_request"), 400
        return render_template("error.html", code=400,
                               message="The request could not be understood."), 400

    @app.errorhandler(403)
    def _forbidden(error):
        if _wants_json():
            return jsonify(success=False, error="Forbidden", code="forbidden"), 403
        return render_template("error.html", code=403,
                               message="You do not have access to this resource."), 403

    @app.errorhandler(404)
    def _not_found(error):
        if _wants_json():
            return jsonify(success=False, error="Not found", code="not_found"), 404
        return render_template("error.html", code=404,
                               message="The page you requested was not found."), 404

    @app.errorhandler(413)
    def _too_large(error):
        limit_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        if _wants_json():
            return jsonify(success=False, error=f"Upload exceeds {limit_mb} MB limit",
                           code="payload_too_large"), 413
        return render_template("error.html", code=413,
                               message=f"The upload exceeds the {limit_mb} MB limit."), 413

    @app.errorhandler(429)
    def _rate_limited(error):
        if _wants_json():
            return jsonify(success=False, error="Too many requests. Please slow down.",
                           code="rate_limited"), 429
        return render_template("error.html", code=429,
                               message="Too many requests. Please wait and try again."), 429

    @app.errorhandler(500)
    def _server_error(error):  # pragma: no cover - defensive
        app.logger.exception("Unhandled server error")
        if _wants_json():
            return jsonify(success=False, error="Internal server error",
                           code="server_error"), 500
        return render_template("error.html", code=500,
                               message="An internal error occurred."), 500

    from flask_wtf.csrf import CSRFError

    @app.errorhandler(CSRFError)
    def _csrf_error(error):
        if _wants_json():
            return jsonify(success=False, error="CSRF validation failed",
                           code="csrf_failed"), 400
        return render_template("error.html", code=400,
                               message="Your session expired. Please reload the page."), 400


def _register_security_headers(app: Flask) -> None:
    @app.after_request
    def _set_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(self), microphone=(), geolocation=(), payment=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "img-src 'self' data: blob:; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; "
            "media-src 'self' blob:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'",
        )
        if app.config.get("ENV") == "production":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


def _register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db():
        """Create all database tables."""
        db.create_all()
        click.echo("Database tables created.")

    @app.cli.command("purge-scans")
    @click.option("--days", default=0, help="Delete scans older than N days (0 = use per-user settings).")
    def purge_scans(days):
        """Delete old scans according to retention settings."""
        from models import Scan, User

        cutoff_map = {}
        if days:
            from datetime import timedelta

            cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
            cutoff_map[None] = cutoff

        removed = 0
        for user in User.query.all():
            settings = user.ensure_settings()
            retention = days or settings.retention_days or 0
            if retention <= 0:
                continue
            from datetime import timedelta

            cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=retention)
            removed += (
                Scan.query.filter(Scan.user_id == user.id, Scan.created_at < cutoff)
                .delete(synchronize_session=False)
            )
        db.session.commit()
        click.echo(f"Removed {removed} scans.")


# Module-level app for `flask --app app run` and WSGI servers.
app = create_app()


if __name__ == "__main__":
    import os

    with app.app_context():
        db.create_all()
        app.logger.info("Digital Guardian starting (debug=%s)", app.debug)
    app.run(host=os.getenv("HOST", "127.0.0.1"),
            port=int(os.getenv("PORT", 5000)), debug=app.debug)
