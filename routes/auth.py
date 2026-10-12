"""Digital Guardian - web authentication routes (cookie sessions)."""

from __future__ import annotations

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from extensions import db, limiter
from models import User
from services.validation import (
    ValidationError,
    validate_email,
    validate_name,
    validate_password,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register_page():
    if current_user.is_authenticated:
        return redirect(url_for("web.dashboard"))

    if request.method == "POST":
        try:
            name = validate_name(request.form.get("name"))
            email = validate_email(request.form.get("email"))
            password = validate_password(request.form.get("password"))
            confirm = request.form.get("confirm_password", "")
            if password != confirm:
                raise ValidationError("Passwords do not match.", "confirm_password")
        except ValidationError as exc:
            flash(exc.message, "danger")
            return redirect(url_for("auth.register_page"))

        if User.query.filter_by(email=email).first():
            flash("An account already exists with this email.", "danger")
            return redirect(url_for("auth.register_page"))

        user = User(name=name, email=email, guardian_mode=True)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        user.ensure_settings()
        db.session.commit()

        flash("Registration successful. Please login.", "success")
        return redirect(url_for("auth.login_page"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("15 per minute", methods=["POST"])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("web.dashboard"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user, remember=bool(request.form.get("remember")))
            user.ensure_settings()
            db.session.commit()
            flash("Welcome back to Digital Guardian.", "success")
            return redirect(url_for("web.dashboard"))

        # Generic message to avoid leaking which accounts exist.
        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("web.home"))
