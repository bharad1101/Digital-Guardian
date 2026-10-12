"""Analysis endpoints: text, URL, QR, image, and the legacy QR route."""

PHISHING_TEXT = (
    "URGENT! Your bank account is blocked. Verify now at "
    "http://paypal-secure-login.tk/verify and share your OTP to avoid suspension."
)


def test_analyze_text_flags_phishing(auth_client):
    resp = auth_client.post("/api/v1/analyze/text", json={"text": PHISHING_TEXT})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["risk_score"] >= 40
    assert data["threat_level"] in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"}
    assert data["indicators"]
    assert data["recommendations"]


def test_analyze_text_rejects_empty(auth_client):
    resp = auth_client.post("/api/v1/analyze/text", json={"text": "   "})
    assert resp.status_code == 422


def test_analyze_url_detects_shortener_and_risky_tld(auth_client):
    resp = auth_client.post("/api/v1/analyze/url",
                            json={"url": "http://bit.ly/3xAbC"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["risk_score"] > 0
    assert any("shorten" in (ind or "").lower() for ind in data["indicators"])


def test_analyze_url_rejects_invalid(auth_client):
    resp = auth_client.post("/api/v1/analyze/url", json={"url": "not a url"})
    assert resp.status_code == 422


def test_analyze_qr_classifies_url(auth_client):
    resp = auth_client.post("/api/v1/analyze/qr",
                            json={"payload": "http://evil.example.com/steal"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["payload"]["type"] == "URL"


def test_analyze_qr_wifi_payload(auth_client):
    resp = auth_client.post("/api/v1/analyze/qr",
                            json={"payload": "WIFI:T:WPA;S:MyNet;P:secret123;;"})
    assert resp.status_code == 200
    assert resp.get_json()["payload"]["type"] == "WiFi"


def test_analyze_image_accepts_png(auth_client, png_bytes):
    resp = auth_client.post(
        "/api/v1/analyze/image",
        data={"image": (__import__("io").BytesIO(png_bytes), "test.png")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    assert resp.get_json()["input_type"] in {"image", "screenshot"}


def test_analyze_image_rejects_non_image(auth_client):
    resp = auth_client.post(
        "/api/v1/analyze/image",
        data={"image": (__import__("io").BytesIO(b"not an image"), "x.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code in {400, 415, 422}


def test_legacy_qr_endpoint_shape(auth_client):
    resp = auth_client.post("/api/analyze-qr", json={"payload": "http://evil.example.com"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "qr_analysis" in data
    assert "analysis" in data
    assert data["qr_analysis"]["payload"] == "http://evil.example.com"


def test_legacy_qr_requires_payload_text(auth_client):
    resp = auth_client.post("/api/analyze-qr", json={"payload": 123})
    assert resp.status_code == 400


def test_analysis_allows_anonymous_but_does_not_persist(app, client):
    # Analysis is intentionally available without login, but anonymous
    # results are never written to any history.
    resp = client.post("/api/v1/analyze/text", json={"text": "anonymous one-off analysis"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["saved"] is False
    from models import Scan
    with app.app_context():
        assert Scan.query.count() == 0


def test_analysis_is_persisted_to_history(auth_client):
    before = len(auth_client.get("/api/v1/history").get_json()["items"])
    auth_client.post("/api/v1/analyze/text", json={"text": "unique persisted content here"})
    after = auth_client.get("/api/v1/history").get_json()["items"]
    assert len(after) == before + 1
