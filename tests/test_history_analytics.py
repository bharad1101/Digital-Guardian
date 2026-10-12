"""History, dashboard and analytics endpoints."""


def test_dashboard_summary_empty(auth_client):
    data = auth_client.get("/api/v1/dashboard/summary").get_json()["summary"]
    assert data["total_scans"] == 0
    assert data["guardian_score"] == 100


def test_analytics_empty(auth_client):
    data = auth_client.get("/api/v1/analytics").get_json()["analytics"]
    assert data["total_scans"] == 0
    assert len(data["trend"]) == 7


def test_history_filters_by_type(auth_client):
    auth_client.post("/api/v1/analyze/text", json={"text": "some plain text message"})
    auth_client.post("/api/v1/analyze/url", json={"url": "http://bit.ly/xyz"})

    text_only = auth_client.get("/api/v1/history?type=text").get_json()["items"]
    url_only = auth_client.get("/api/v1/history?type=url").get_json()["items"]
    assert all(item["input_type"] == "text" for item in text_only)
    assert all(item["input_type"] == "url" for item in url_only)


def test_history_search(auth_client):
    auth_client.post("/api/v1/analyze/text", json={"text": "unique keyword zzebra in message"})
    results = auth_client.get("/api/v1/history?q=zzebra").get_json()["items"]
    assert len(results) == 1


def test_delete_scan(auth_client):
    auth_client.post("/api/v1/analyze/text", json={"text": "to be deleted shortly"})
    items = auth_client.get("/api/v1/history").get_json()["items"]
    assert items
    scan_id = items[0]["id"]
    resp = auth_client.delete(f"/api/v1/history/{scan_id}")
    assert resp.status_code in {200, 204}
    remaining = auth_client.get("/api/v1/history").get_json()["items"]
    assert all(item["id"] != scan_id for item in remaining)


def test_delete_all_history(auth_client):
    auth_client.post("/api/v1/analyze/text", json={"text": "one"})
    auth_client.post("/api/v1/analyze/text", json={"text": "two"})
    assert auth_client.get("/api/v1/history").get_json()["items"]
    resp = auth_client.delete("/api/v1/history")
    assert resp.status_code in {200, 204}
    assert auth_client.get("/api/v1/history").get_json()["items"] == []


def test_settings_update(auth_client):
    resp = auth_client.patch("/api/v1/settings",
                             json={"notifications_enabled": False, "retention_days": 15})
    assert resp.status_code == 200
    data = auth_client.get("/api/v1/settings").get_json()
    assert data["settings"]["retention_days"] == 15
    assert data["settings"]["notifications_enabled"] is False
