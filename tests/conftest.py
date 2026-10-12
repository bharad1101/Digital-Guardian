"""Shared pytest fixtures for the Digital Guardian test suite."""

import io
import sys
from pathlib import Path

import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from extensions import db  # noqa: E402

PASSWORD = "Str0ngPass!23"
EMAIL = "tester@example.com"


@pytest.fixture()
def app():
    application = create_app("testing")
    with application.app_context():
        db.create_all()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def registered_user(app):
    client = app.test_client()
    client.post("/register", data={
        "name": "Test User",
        "email": EMAIL,
        "password": PASSWORD,
        "confirm_password": PASSWORD,
    }, follow_redirects=True)
    return client


@pytest.fixture()
def auth_client(registered_user):
    registered_user.post("/login", data={"email": EMAIL, "password": PASSWORD},
                         follow_redirects=True)
    return registered_user


@pytest.fixture()
def png_bytes():
    buf = io.BytesIO()
    Image.new("RGB", (48, 48), (20, 120, 200)).save(buf, format="PNG")
    buf.seek(0)
    return buf.getvalue()


@pytest.fixture()
def bearer_token(client):
    client.post("/register", data={
        "name": "Mobile User",
        "email": "mobile@example.com",
        "password": PASSWORD,
        "confirm_password": PASSWORD,
    }, follow_redirects=True)
    resp = client.post("/api/v1/auth/login",
                       json={"email": "mobile@example.com", "password": PASSWORD})
    return resp.get_json()["token"]
