"""Report storage and tamper-evident evidence-chain tests."""

from __future__ import annotations

from app.engine.evidence import verify_evidence_chain


def _create_message(client) -> dict:
    response = client.post(
        "/api/v1/messages/analyze",
        json={
            "text": "Congratulations! You won a prize. Pay the processing fee at http://claim-prize.xyz",
            "language": "en",
            "channel": "sms",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["report"]


def test_report_list_get_markdown_and_verify(client):
    report = _create_message(client)
    report_id = report["id"]

    listing = client.get("/api/v1/investigations", params={"limit": 50})
    assert listing.status_code == 200
    assert any(item["id"] == report_id for item in listing.json())

    filtered = client.get("/api/v1/investigations", params={"module": "message"})
    assert filtered.status_code == 200
    assert all(item["module"] == "message" for item in filtered.json())

    fetched = client.get(f"/api/v1/investigations/{report_id}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == report_id

    markdown = client.get(f"/api/v1/investigations/{report_id}/markdown")
    assert markdown.status_code == 200
    assert markdown.headers["content-type"].startswith("text/markdown")
    assert "# ThreatLens Investigation Report" in markdown.text

    verified = client.post(f"/api/v1/investigations/{report_id}/verify")
    assert verified.status_code == 200
    body = verified.json()
    assert body["valid"] is True
    assert body["errors"] == []
    assert body["evidence_count"] == len(report["evidence"])


def test_tampered_evidence_breaks_the_chain(client, services, settings):
    report_id = _create_message(client)["id"]
    report = services.reports.get(report_id)
    assert report is not None
    tampered = [item.model_copy(deep=True) for item in report.evidence]
    tampered[0].summary = "A completely different observation"
    valid, errors = verify_evidence_chain(tampered, settings.signing_key)
    assert valid is False
    assert any("sha256 mismatch" in error for error in errors)
    assert any("HMAC" in error for error in errors)


def test_reordered_evidence_breaks_the_chain(client, services, settings):
    report_id = _create_message(client)["id"]
    report = services.reports.get(report_id)
    assert report is not None
    reordered = [item.model_copy(deep=True) for item in report.evidence]
    assert len(reordered) >= 2
    reordered[0], reordered[1] = reordered[1], reordered[0]
    valid, errors = verify_evidence_chain(reordered, settings.signing_key)
    assert valid is False
    assert errors
