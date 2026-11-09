"""Offline test fixtures: no network, no Hugging Face token, real forensic tools."""

from __future__ import annotations

import io

import pytest
from app.config import Settings
from app.main import create_app
from app.services import ForensicServices
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def settings() -> Settings:
    return Settings(
        llm_mode="offline",
        allow_network=False,
        environment="test",
        evidence_signing_key="test-signing-key",
        _env_file=None,
    )


@pytest.fixture(scope="session")
def services(settings: Settings) -> ForensicServices:
    return ForensicServices(settings)


@pytest.fixture(scope="session")
def client(services: ForensicServices, settings: Settings):
    app = create_app(settings=settings, services=services)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def qr_image() -> bytes:
    qrcode = pytest.importorskip("qrcode")
    image = qrcode.make(
        "upi://pay?pa=scammer@upi&pn=Refund%20Officer&am=4999&cu=INR&tn=Refund"
    )
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


@pytest.fixture()
def screenshot() -> bytes:
    from PIL import Image, ImageDraw

    image = Image.new("RGB", (900, 560), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle([20, 20, 880, 130], fill="#1a4b8c")
    draw.text((40, 60), "STATE BANK OF INDIA - Net Banking Login", fill="white")
    draw.text((40, 220), "User ID", fill="black")
    draw.rectangle([40, 240, 520, 285], outline="black")
    draw.text((40, 330), "Password", fill="black")
    draw.rectangle([40, 350, 520, 395], outline="black")
    draw.text((40, 500), "https://sbi-secure-login.xyz/login", fill="black")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


@pytest.fixture()
def eml_bytes() -> bytes:
    return b"\r\n".join(
        [
            b'From: "SBI Accounts" <manager@sbi-verify.xyz>',
            b'Reply-To: "SBI Support" <support@another-domain.example>',
            b"Return-Path: <bounce@mailer.example>",
            b"To: victim@example.com",
            b"Subject: URGENT: Updated bank details required",
            b"Date: Sat, 07 Nov 2026 10:00:00 +0000",
            b"Message-ID: <abc123@sbi-verify.xyz>",
            b"Authentication-Results: mx.example; spf=fail smtp.mailfrom=sbi-verify.xyz; "
            b"dkim=fail; dmarc=fail",
            b"MIME-Version: 1.0",
            b'Content-Type: multipart/mixed; boundary="BOUNDARY"',
            b"",
            b"--BOUNDARY",
            b"Content-Type: text/plain; charset=utf-8",
            b"Content-Transfer-Encoding: 7bit",
            b"",
            b"Dear Customer,",
            b"",
            b"Our records show your account is suspended. Please update your bank details",
            b"and confirm the urgent payment instruction using this link:",
            b"http://sbi-verify.xyz/account/verify?token=123",
            b"",
            b"For security, reply with the OTP sent to your phone and confirm your",
            b"password. This is a final notice from the managing director.",
            b"",
            b"Regards,",
            b"SBI Accounts Team",
            b"",
            b"--BOUNDARY",
            b'Content-Type: application/pdf; name="invoice_2026.pdf"',
            b'Content-Disposition: attachment; filename="invoice_2026.pdf"',
            b"Content-Transfer-Encoding: base64",
            b"",
            b"JVBERi0xLjQKJcOkw7zDtsOfCjIgMCBvYmoKPDwvTGVuZ3RoIDUgMCBSPj4Kc3RyZWFtCkJUCi9GMSAxMiBUZgp",
            b"CjEwIDcwMCBUZCAoSW52b2ljZSkgVGogRVQKZW5kc3RyZWFtCmVuZG9iagp0cmFpbGVyCjw8L1Jvb3QgMSAwIF",
            b"I+PgolJUVPRgo=",
            b"",
            b"--BOUNDARY--",
        ]
    )
