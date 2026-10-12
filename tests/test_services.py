"""Unit tests for the analysis services (no HTTP layer)."""

from services import qr_analyzer, url_analyzer, validation
from services.auth_tokens import issue_token, revoke_tokens, verify_token
from services.threat_engine import level_label, normalize_level, score_to_level


def test_score_to_level_thresholds():
    assert score_to_level(0) == "SAFE"
    assert score_to_level(20) == "SAFE"
    assert score_to_level(21) == "LOW_RISK"
    assert score_to_level(40) == "LOW_RISK"
    assert score_to_level(41) == "SUSPICIOUS"
    assert score_to_level(61) == "HIGH_RISK"
    assert score_to_level(100) == "CRITICAL"


def test_level_normalization_handles_legacy_values():
    assert normalize_level("HIGH RISK") == "HIGH_RISK"
    assert level_label("HIGH RISK") == "High Risk"
    assert level_label("LOW_RISK") == "Low Risk"


def test_url_analyzer_flags_shortener():
    report = url_analyzer.analyze_url("http://bit.ly/abc")
    assert report["risk_points"] > 0
    assert report["is_shortener"] is True


def test_url_analyzer_flags_ip_host():
    report = url_analyzer.analyze_url("http://192.168.1.1/login")
    assert report["is_ip_literal"] is True


def test_url_analyzer_flags_userinfo_trick():
    report = url_analyzer.analyze_url("http://paypal.com@evil.example.com")
    assert report["has_userinfo"] is True


def test_url_analyzer_flags_punycode():
    report = url_analyzer.analyze_url("http://xn--80ak6aa92e.com/")
    assert report["has_punycode"] is True


def test_url_analyzer_safe_url_low_score():
    report = url_analyzer.analyze_url("https://www.example.com/about")
    assert report["risk_points"] == 0


def test_qr_classifies_wifi():
    result = qr_analyzer.analyze_qr("WIFI:T:WPA;S:Net;P:pass;;")
    assert result["payload_type"] == qr_analyzer.TYPE_WIFI


def test_qr_classifies_url():
    result = qr_analyzer.analyze_qr("https://example.com")
    assert result["payload_type"] == qr_analyzer.TYPE_URL


def test_qr_flags_dangerous_scheme():
    result = qr_analyzer.analyze_qr("javascript:alert(1)")
    assert result["payload_type"] == qr_analyzer.TYPE_UNKNOWN
    assert any("non-web scheme" in ind.lower() for ind in result["indicators"])


def test_qr_empty_rejected():
    result = qr_analyzer.analyze_qr("   ")
    assert result["payload_type"] == qr_analyzer.TYPE_EMPTY


def test_validation_email():
    assert validation.validate_email("a@b.com") == "a@b.com"
    try:
        validation.validate_email("not-an-email")
        assert False, "expected ValidationError"
    except validation.ValidationError:
        pass


def test_validation_password_strength():
    try:
        validation.validate_password("123")
        assert False, "expected ValidationError"
    except validation.ValidationError:
        pass
    assert validation.validate_password("Str0ngPass!23") == "Str0ngPass!23"


def test_validation_text_length_cap():
    try:
        validation.validate_text("x" * 20000)
        assert False, "expected ValidationError for over-long text"
    except validation.ValidationError:
        pass
    assert validation.validate_text("x" * 100) == "x" * 100


def test_auth_tokens_roundtrip(app):
    from models import User
    with app.app_context():
        user = User(name="Tok", email="tok@example.com")
        user.set_password("Str0ngPass!23")
        user.token_version = 0
        from extensions import db
        db.session.add(user)
        db.session.commit()
        token = issue_token(user)
        assert verify_token(token).id == user.id


def test_auth_tokens_revoked_by_version(app):
    from models import User
    from extensions import db
    with app.app_context():
        user = User(name="Tok2", email="tok2@example.com")
        user.set_password("Str0ngPass!23")
        user.token_version = 0
        db.session.add(user)
        db.session.commit()
        token = issue_token(user)
        revoke_tokens(user)
        assert verify_token(token) is None
