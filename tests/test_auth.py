"""Authentication: web forms, API tokens, CSRF, and isolation."""

from tests.conftest import EMAIL, PASSWORD


def test_register_creates_user(app, client):
    resp = client.post("/register", data={
        "name": "Alice", "email": "alice@example.com",
        "password": PASSWORD, "confirm_password": PASSWORD,
    }, follow_redirects=True)
    assert resp.status_code == 200
    from models import User
    with app.app_context():
        user = User.query.filter_by(email="alice@example.com").first()
        assert user is not None
        assert user.check_password(PASSWORD)
        assert user.ensure_settings() is not None


def test_register_rejects_mismatched_passwords(app, client):
    client.post("/register", data={
        "name": "Bob", "email": "bob@example.com",
        "password": PASSWORD, "confirm_password": "different",
    }, follow_redirects=True)
    from models import User
    with app.app_context():
        assert User.query.filter_by(email="bob@example.com").first() is None


def test_register_rejects_weak_password(app, client):
    client.post("/register", data={
        "name": "Weak", "email": "weak@example.com",
        "password": "123", "confirm_password": "123",
    }, follow_redirects=True)
    from models import User
    with app.app_context():
        assert User.query.filter_by(email="weak@example.com").first() is None


def test_login_logout_flow(auth_client):
    assert auth_client.get("/dashboard").status_code == 200
    auth_client.get("/logout", follow_redirects=True)
    assert auth_client.get("/dashboard").status_code == 302


def test_api_login_returns_token(client, registered_user):
    resp = client.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["token"]
    assert data["user"]["email"] == EMAIL


def test_api_login_rejects_bad_password(client, registered_user):
    resp = client.post("/api/v1/auth/login",
                       json={"email": EMAIL, "password": "wrong-password"})
    assert resp.status_code == 401


def test_bearer_token_authenticates(client, bearer_token):
    headers = {"Authorization": "Bearer " + bearer_token}
    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["user"]["email"] == "mobile@example.com"


def test_bearer_token_required_for_mobile(app):
    fresh = app.test_client()
    assert fresh.get("/api/v1/auth/me").status_code == 401


def test_invalid_bearer_token_rejected(client):
    resp = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_logout_revokes_tokens(app, client, bearer_token):
    headers = {"Authorization": "Bearer " + bearer_token}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    client.post("/api/v1/auth/logout", headers=headers)
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_history_isolation_between_users(app):
    a = app.test_client()
    b = app.test_client()
    a.post("/register", data={"name": "A", "email": "a@example.com",
                              "password": PASSWORD, "confirm_password": PASSWORD})
    b.post("/register", data={"name": "B", "email": "b@example.com",
                              "password": PASSWORD, "confirm_password": PASSWORD})
    a.post("/login", data={"email": "a@example.com", "password": PASSWORD})
    b.post("/login", data={"email": "b@example.com", "password": PASSWORD})

    a.post("/api/v1/analyze/text", json={"text": "a message about a unique topic here"})
    b.post("/api/v1/analyze/text", json={"text": "another different message entirely"})

    a_items = a.get("/api/v1/history").get_json()["items"]
    b_items = b.get("/api/v1/history").get_json()["items"]
    assert len(a_items) == 1
    assert len(b_items) == 1
    assert a_items[0]["id"] != b_items[0]["id"]
