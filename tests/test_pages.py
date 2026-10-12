"""Website page rendering tests."""

PUBLIC_PAGES = ["/", "/login", "/register", "/privacy"]

AUTH_PAGES = [
    "/dashboard", "/scanner", "/lens", "/qr-scanner", "/image",
    "/history", "/analytics", "/settings",
]


def test_public_pages_render(client):
    for path in PUBLIC_PAGES:
        resp = client.get(path)
        assert resp.status_code == 200, path


def test_protected_pages_redirect_when_anonymous(client):
    for path in AUTH_PAGES:
        resp = client.get(path)
        assert resp.status_code == 302, path
        assert "/login" in resp.headers.get("Location", "")


def test_protected_pages_render_when_authenticated(auth_client):
    for path in AUTH_PAGES:
        resp = auth_client.get(path)
        assert resp.status_code == 200, path


def test_unknown_page_returns_404(client):
    assert client.get("/definitely-not-a-page").status_code == 404
