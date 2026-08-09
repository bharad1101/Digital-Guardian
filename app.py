from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from collections import Counter

from services.threat_engine import analyze_threat


app = Flask(__name__)

app.config["SECRET_KEY"] = "digital-guardian-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///digital_guardian.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please login to access Digital Guardian."


# ==========================================================
# USER MODEL
# ==========================================================

class User(UserMixin, db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    guardian_mode = db.Column(
        db.Boolean,
        default=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# ==========================================================
# SCAN MODEL
# ==========================================================

class Scan(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    channel = db.Column(
        db.String(50),
        nullable=False
    )

    content = db.Column(
        db.Text,
        nullable=False
    )

    threat_type = db.Column(
        db.String(100)
    )

    scam_category = db.Column(
        db.String(100)
    )

    risk_score = db.Column(
        db.Integer,
        default=0
    )

    threat_level = db.Column(
        db.String(50)
    )

    recommendation = db.Column(
        db.Text
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# ==========================================================
# LOGIN MANAGER
# ==========================================================

@login_manager.user_loader
def load_user(user_id):

    return db.session.get(
        User,
        int(user_id)
    )


# ==========================================================
# HOME
# ==========================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ==========================================================
# REGISTER
# ==========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        name = request.form["name"].strip()

        email = request.form[
            "email"
        ].strip().lower()

        password = request.form[
            "password"
        ]

        confirm_password = request.form[
            "confirm_password"
        ]

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        existing_user = User.query.filter_by(
            email=email
        ).first()

        if existing_user:

            flash(
                "An account already exists with this email.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        hashed_password = generate_password_hash(
            password
        )

        user = User(
            name=name,
            email=email,
            password=hashed_password
        )

        db.session.add(user)
        db.session.commit()

        flash(
            "Registration successful. Please login.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# ==========================================================
# LOGIN
# ==========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        email = request.form[
            "email"
        ].strip().lower()

        password = request.form[
            "password"
        ]

        user = User.query.filter_by(
            email=email
        ).first()

        if user and check_password_hash(
            user.password,
            password
        ):

            login_user(user)

            flash(
                "Welcome back to Digital Guardian.",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid email or password.",
            "danger"
        )

    return render_template(
        "login.html"
    )


# ==========================================================
# DASHBOARD
# ==========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    scans = Scan.query.filter_by(
        user_id=current_user.id
    ).order_by(
        Scan.created_at.desc()
    ).all()

    total_scans = len(scans)

    safe_scans = sum(
        1
        for scan in scans
        if scan.risk_score <= 30
    )

    suspicious_scans = sum(
        1
        for scan in scans
        if 31 <= scan.risk_score <= 70
    )

    critical_scans = sum(
        1
        for scan in scans
        if scan.risk_score > 70
    )

    average_risk = 0

    if total_scans:

        average_risk = round(
            sum(
                scan.risk_score
                for scan in scans
            ) / total_scans
        )

    guardian_score = max(
        0,
        100 - average_risk
    )

    channels = [
        scan.channel
        for scan in scans
    ]

    categories = [
        scan.scam_category
        for scan in scans
        if scan.scam_category
        and scan.scam_category != "None"
    ]

    most_common_channel = "No data"
    most_common_category = "No threats detected"

    if channels:

        most_common_channel = Counter(
            channels
        ).most_common(1)[0][0]

    if categories:

        most_common_category = Counter(
            categories
        ).most_common(1)[0][0]

    if total_scans == 0:

        conclusion = (
            "No scans have been analysed yet. "
            "Use the Digital Guardian scanner to begin building "
            "your personal cybersecurity profile."
        )

    elif average_risk <= 20:

        conclusion = (
            "Your recent scan history shows a low overall threat level. "
            "Continue verifying unexpected links, payment requests, "
            "and requests for sensitive information."
        )

    elif average_risk <= 50:

        conclusion = (
            "Your scan history contains several suspicious items. "
            "Exercise caution with unexpected messages, links, "
            "financial requests, and unknown senders."
        )

    elif average_risk <= 70:

        conclusion = (
            "Digital Guardian has detected a significant level of "
            "suspicious or high-risk activity. Avoid interacting with "
            "unverified senders and verify sensitive requests independently."
        )

    else:

        conclusion = (
            "Your recent scan history contains a high concentration "
            "of serious threats. Do not share OTPs, passwords, banking "
            "details, or make payments without independent verification."
        )

    return render_template(
        "dashboard.html",
        scans=scans[:5],
        total_scans=total_scans,
        safe_scans=safe_scans,
        suspicious_scans=suspicious_scans,
        critical_scans=critical_scans,
        average_risk=average_risk,
        guardian_score=guardian_score,
        most_common_channel=most_common_channel,
        most_common_category=most_common_category,
        conclusion=conclusion
    )


# ==========================================================
# GUARDIAN MODE
# ==========================================================

@app.route(
    "/guardian-mode",
    methods=["POST"]
)
@login_required
def guardian_mode():

    current_user.guardian_mode = (
        not current_user.guardian_mode
    )

    db.session.commit()

    if current_user.guardian_mode:

        flash(
            "Guardian Mode activated.",
            "success"
        )

    else:

        flash(
            "Guardian Mode paused.",
            "warning"
        )

    return redirect(
        url_for("dashboard")
    )


# ==========================================================
# SCANNER
# ==========================================================

@app.route(
    "/scanner",
    methods=["GET", "POST"]
)
@login_required
def scanner():

    result = None

    submitted_content = ""

    selected_channel = "Message"

    if request.method == "POST":

        selected_channel = request.form[
            "channel"
        ]

        submitted_content = request.form[
            "content"
        ].strip()

        if not submitted_content:

            flash(
                "Please enter content to analyse.",
                "warning"
            )

            return redirect(
                url_for("scanner")
            )

        result = analyze_threat(
            submitted_content,
            selected_channel
        )

        scan = Scan(
            user_id=current_user.id,
            channel=selected_channel,
            content=submitted_content,
            threat_type=result[
                "threat_type"
            ],
            scam_category=result[
                "scam_category"
            ],
            risk_score=result[
                "risk_score"
            ],
            threat_level=result[
                "threat_level"
            ],
            recommendation=result[
                "recommendation"
            ]
        )

        db.session.add(scan)
        db.session.commit()

    return render_template(
        "scanner.html",
        result=result,
        submitted_content=submitted_content,
        selected_channel=selected_channel
    )


# ==========================================================
# HISTORY
# ==========================================================

@app.route("/history")
@login_required
def history():

    channel_filter = request.args.get(
        "channel",
        ""
    )

    level_filter = request.args.get(
        "level",
        ""
    )

    query = Scan.query.filter_by(
        user_id=current_user.id
    )

    if channel_filter:

        query = query.filter_by(
            channel=channel_filter
        )

    if level_filter:

        query = query.filter_by(
            threat_level=level_filter
        )

    scans = query.order_by(
        Scan.created_at.desc()
    ).all()

    return render_template(
        "history.html",
        scans=scans,
        channel_filter=channel_filter,
        level_filter=level_filter
    )


# ==========================================================
# ANALYTICS
# ==========================================================

@app.route("/analytics")
@login_required
def analytics():

    scans = Scan.query.filter_by(
        user_id=current_user.id
    ).all()

    total_scans = len(scans)

    average_risk = 0

    if total_scans:

        average_risk = round(
            sum(
                scan.risk_score
                for scan in scans
            ) / total_scans
        )

    channel_counter = Counter(
        scan.channel
        for scan in scans
    )

    category_counter = Counter(
        scan.scam_category
        for scan in scans
        if scan.scam_category
        and scan.scam_category != "None"
    )

    level_counter = Counter(
        scan.threat_level
        for scan in scans
    )

    most_risky_channel = "No data"

    if scans:

        channel_scores = {}

        for scan in scans:

            if scan.channel not in channel_scores:

                channel_scores[
                    scan.channel
                ] = []

            channel_scores[
                scan.channel
            ].append(
                scan.risk_score
            )

        channel_averages = {
            channel: round(
                sum(scores) / len(scores)
            )
            for channel, scores
            in channel_scores.items()
        }

        most_risky_channel = max(
            channel_averages,
            key=channel_averages.get
        )

    return render_template(
        "analytics.html",
        total_scans=total_scans,
        average_risk=average_risk,
        channel_counter=channel_counter,
        category_counter=category_counter,
        level_counter=level_counter,
        most_risky_channel=most_risky_channel
    )


# ==========================================================
# LOGOUT
# ==========================================================

@app.route("/logout")
@login_required
def logout():

    logout_user()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("home")
    )


# ==========================================================
# START APPLICATION
# ==========================================================

if __name__ == "__main__":

    with app.app_context():

        db.create_all()

    app.run(
        debug=True,
        port=5000
    )
