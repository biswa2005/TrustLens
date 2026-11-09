"""Generate local sample inputs for manual testing of all four modules.

Creates files under `samples/`:
    samples/message_sms.json       -> POST /api/v1/messages/analyze
    samples/qrcode.png             -> POST /api/v1/qr/analyze
    samples/screenshot_login.png   -> POST /api/v1/visual/analyze
    samples/bec_email.eml          -> POST /api/v1/email/analyze

The samples are intentionally fraudulent-looking fixtures for a security
product demo. They are inert: no live URLs are contacted when generating them.

Usage:
    python scripts/generate_samples.py
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "samples"

MESSAGE = {
    "text": (
        "URGENT: Your SBI account has been blocked for non-KYC. Verify immediately "
        "at http://sbi-kyc-verify.xyz/login and pay Rs.499 to reactivate. "
        "Share the OTP with our verification officer. - SBI Accounts Team"
    ),
    "language": "en",
    "channel": "sms",
    "sender": "+919999999999",
}

QR_PAYLOAD = "upi://pay?pa=scammer@upi&pn=Refund%20Officer&am=4999&cu=INR&tn=Refund"

EML = b"""From: "SBI Accounts" <manager@sbi-verify.xyz>
Reply-To: "SBI Support" <support@another-domain.example>
Return-Path: <bounce@mailer.example>
To: victim@example.com
Subject: URGENT: Updated bank details required
Date: Sat, 07 Nov 2026 10:00:00 +0000
Message-ID: <abc123@sbi-verify.xyz>
Authentication-Results: mx.example; spf=fail smtp.mailfrom=sbi-verify.xyz; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

Dear Customer,

Our records show your account is suspended. Please update your bank details and
confirm the urgent payment instruction using this link:
http://sbi-verify.xyz/account/verify?token=123

For security, reply with the OTP sent to your phone and confirm your password.
This is a final notice from the managing director.

Regards,
SBI Accounts Team

--BOUNDARY
Content-Type: application/pdf; name="invoice_2026.pdf"
Content-Disposition: attachment; filename="invoice_2026.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcOkw7zDtsOfCjIgMCBvYmoKPDwvTGVuZ3RoIDUgMCBSPj4Kc3RyZWFtCkJUCi9GMSAxMiBUZgp
CjEwIDcwMCBUZCAoSW52b2ljZSkgVGogRVQKZW5kc3RyZWFtCmVuZG9iagp0cmFpbGVyCjw8L1Jvb3QgMSAwIF
I+PgolJUVPRgo=

--BOUNDARY--
"""


def build_screenshot() -> bytes:
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
    from io import BytesIO

    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def build_qr() -> bytes:
    from io import BytesIO

    import qrcode

    image = qrcode.make(QR_PAYLOAD)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def main() -> None:
    OUT.mkdir(exist_ok=True)

    (OUT / "message_sms.json").write_text(
        json.dumps(MESSAGE, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (OUT / "bec_email.eml").write_bytes(EML)

    try:
        (OUT / "qrcode.png").write_bytes(build_qr())
    except ImportError:
        print("! qrcode not installed; skipped qrcode.png (pip install -r requirements-dev.txt)")
    try:
        (OUT / "screenshot_login.png").write_bytes(build_screenshot())
    except ImportError:
        print("! Pillow not installed; skipped screenshot_login.png")

    print(f"Samples written to {OUT}")
    for path in sorted(OUT.iterdir()):
        print(f"  {path.name} ({path.stat().st_size} bytes)")
    print()
    print("Try them:")
    print("  curl -s localhost:8000/api/v1/messages/analyze -H 'Content-Type: application/json' "
          "-d @samples/message_sms.json | head -c 400")
    print("  curl -s localhost:8000/api/v1/qr/analyze -F image=@samples/qrcode.png "
          "-F caption='Scan to receive your refund'")
    print("  curl -s localhost:8000/api/v1/visual/analyze -F image=@samples/screenshot_login.png "
          "-F brand_hint='State Bank of India' -F claimed_url=https://sbi-secure-login.xyz/login")
    print("  curl -s localhost:8000/api/v1/email/analyze -F eml=@samples/bec_email.eml")


if __name__ == "__main__":
    main()
