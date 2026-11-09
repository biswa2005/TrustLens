"""End-to-end module tests: every finding must cite real evidence."""

from __future__ import annotations


def _assert_grounded(report: dict) -> None:
    evidence_ids = {item["id"] for item in report["evidence"]}
    assert evidence_ids, "the report must contain evidence"
    for finding in report["findings"]:
        assert finding["evidence_ids"], f"ungrounded finding: {finding['title']}"
        assert set(finding["evidence_ids"]) <= evidence_ids
    assert report["evidence_chain_valid"] is True
    assert report["degraded"] is True
    assert report["model"]["reasoning_mode"] == "offline-expert-system"
    assert "# ThreatLens Investigation Report" in report["markdown"]
    assert "Evidence ledger" in report["markdown"]


def test_message_investigation(client):
    response = client.post(
        "/api/v1/messages/analyze",
        json={
            "text": (
                "URGENT: Your SBI account is blocked. Verify KYC now at "
                "http://sbi-kyc-verify.xyz/login and pay Rs 499 to reactivate. "
                "Share the OTP with our officer."
            ),
            "language": "en",
            "channel": "sms",
            "sender": "+919999999999",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    report = body["report"]
    assert report["module"] == "message"
    assert body["investigation_id"] == report["id"]
    assert report["risk_score"] >= 45
    assert report["verdict"] in {"likely_malicious", "malicious"}
    titles = " ".join(item["title"] for item in report["findings"]).lower()
    assert "phishing" in titles or "manipulation" in titles
    _assert_grounded(report)

    verify = client.post(f"/api/v1/investigations/{report['id']}/verify")
    assert verify.status_code == 200
    assert verify.json()["valid"] is True


def test_qr_upi_investigation(client, qr_image):
    response = client.post(
        "/api/v1/qr/analyze",
        files={"image": ("refund-qr.png", qr_image, "image/png")},
        data={"caption": "Scan this QR to receive your refund", "language": "en"},
    )
    assert response.status_code == 200, response.text
    report = response.json()["report"]
    assert report["module"] == "qr"
    titles = " ".join(item["title"] for item in report["findings"]).lower()
    assert "upi" in titles
    kinds = {item["kind"] for item in report["evidence"]}
    assert "upi_uri" in kinds
    assert report["risk_score"] >= 20
    _assert_grounded(report)


def test_visual_without_vision_is_not_falsely_benign(client, screenshot):
    response = client.post(
        "/api/v1/visual/analyze",
        files={"image": ("login-page.png", screenshot, "image/png")},
        data={"language": "en"},
    )
    assert response.status_code == 200, response.text
    report = response.json()["report"]
    assert report["module"] == "visual"
    kinds = {item["kind"] for item in report["evidence"]}
    if "vlm_observation" not in kinds and "ocr_text" not in kinds:
        assert report["verdict"] == "inconclusive"
        titles = " ".join(item["title"] for item in report["findings"]).lower()
        assert "could not be visually analysed" in titles
    _assert_grounded(report)


def test_visual_investigates_claimed_lookalike_url(client, screenshot):
    response = client.post(
        "/api/v1/visual/analyze",
        files={"image": ("login-page.png", screenshot, "image/png")},
        data={
            "brand_hint": "State Bank of India",
            "claimed_url": "https://sbi-secure-login.xyz/login",
            "language": "en",
        },
    )
    assert response.status_code == 200, response.text
    report = response.json()["report"]
    url_static = [
        item for item in report["evidence"] if item["kind"] == "url_static"
    ]
    assert url_static, "the claimed URL must be investigated by the URL agent"
    assert report["risk_score"] >= 20
    assert report["verdict"] in {"suspicious", "likely_malicious", "malicious"}
    _assert_grounded(report)


def test_email_bec_and_authentication_claims(client, eml_bytes):
    response = client.post(
        "/api/v1/email/analyze",
        files={"eml": ("bec.eml", eml_bytes, "message/rfc822")},
        data={"language": "en"},
    )
    assert response.status_code == 200, response.text
    report = response.json()["report"]
    assert report["module"] == "email"
    titles = " ".join(item["title"] for item in report["findings"]).lower()
    assert "business email compromise" in titles
    assert "authentication" in titles
    kinds = {item["kind"] for item in report["evidence"]}
    assert "email_auth" in kinds
    assert "email_attachment" in kinds
    assert report["metadata"]["email_auth"] is not None
    assert "Email authentication" in report["markdown"]
    assert report["risk_score"] >= 45
    _assert_grounded(report)
