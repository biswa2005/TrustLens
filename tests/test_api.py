"""API surface tests that run entirely offline."""

from __future__ import annotations


def test_health_reports_degraded_offline_mode(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["degraded"] is True
    assert body["reasoning_mode"] == "offline-expert-system"
    assert body["network_enabled"] is False


def test_meta_lists_all_agents_and_modules(client):
    response = client.get("/api/v1/meta")
    assert response.status_code == 200
    body = response.json()
    assert set(body["modules"]) == {"message", "qr", "visual", "email"}
    assert set(body["capabilities"]["agents"]) == {
        "orchestrator",
        "message",
        "qr",
        "visual",
        "email",
        "url",
        "evidence",
        "report",
    }
    assert body["models"]["reasoning_mode"] == "offline-expert-system"
    assert body["limits"]["max_upload_mb"] > 0


def test_empty_message_is_rejected(client):
    response = client.post("/api/v1/messages/analyze", json={"text": ""})
    assert response.status_code == 422


def test_unknown_module_filter_is_rejected(client):
    response = client.get("/api/v1/investigations", params={"module": "telepathy"})
    assert response.status_code == 422


def test_missing_investigation_returns_404(client):
    assert client.get("/api/v1/investigations/inv_does_not_exist").status_code == 404
    assert (
        client.get("/api/v1/investigations/inv_does_not_exist/markdown").status_code
        == 404
    )
    assert (
        client.post("/api/v1/investigations/inv_does_not_exist/verify").status_code
        == 404
    )


def test_non_email_upload_is_rejected(client):
    response = client.post(
        "/api/v1/email/analyze",
        files={"eml": ("random.bin", b"\x00\x01\x02not an email", "application/octet-stream")},
    )
    assert response.status_code == 422


def test_invalid_image_upload_is_rejected(client):
    response = client.post(
        "/api/v1/qr/analyze",
        files={"image": ("fake.png", b"not really a png", "image/png")},
    )
    assert response.status_code == 422
