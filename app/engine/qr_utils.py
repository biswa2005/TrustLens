"""QR image decoding and payload interpretation."""

from __future__ import annotations

import io
import re
from typing import Any
from urllib.parse import parse_qs

import cv2
import numpy as np
from PIL import Image, ImageOps, UnidentifiedImageError

from app.engine.urls import extract_urls, is_upi_uri, normalize_url, parse_upi_uri
from app.engine.utils import sha256_bytes, truncate

# Guard against decompression bombs before Pillow allocates the bitmap.
Image.MAX_IMAGE_PIXELS = 40_000_000

_WIFI_RE = re.compile(r"(?is)^WIFI:")
_VCARD_RE = re.compile(r"(?is)^BEGIN:VCARD")
_CRYPTO_RE = re.compile(r"(?i)^(bitcoin|ethereum|litecoin|dogecoin|tron|solana):", re.IGNORECASE)
_TEL_RE = re.compile(r"(?i)^tel:")
_SMS_RE = re.compile(r"(?i)^smsto:|^sms:")
_MAILTO_RE = re.compile(r"(?i)^mailto:")
_GEO_RE = re.compile(r"(?i)^geo:")
_OTPAUTH_RE = re.compile(r"(?i)^otpauth:")


class ImageDecodeError(ValueError):
    pass


def open_image(image_bytes: bytes) -> Image.Image:
    if not image_bytes:
        raise ImageDecodeError("Empty upload")
    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.load()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise ImageDecodeError(f"Not a readable image: {exc}") from exc
    if image.width * image.height > 40_000_000:
        raise ImageDecodeError("Image is too large to analyse safely")
    return image


def image_metadata(image: Image.Image, image_bytes: bytes) -> dict[str, Any]:
    return {
        "format": image.format,
        "mode": image.mode,
        "width": image.width,
        "height": image.height,
        "megapixels": round(image.width * image.height / 1_000_000, 2),
        "sha256": sha256_bytes(image_bytes),
        "has_exif": bool(image.getexif()),
    }


def _candidate_arrays(image: Image.Image) -> list[tuple[str, np.ndarray]]:
    rgb = image.convert("RGB")
    base = np.array(rgb)
    gray = cv2.cvtColor(base, cv2.COLOR_RGB2GRAY)
    candidates: list[tuple[str, np.ndarray]] = [("original", gray)]
    if max(gray.shape) < 900:
        factor = max(2, int(900 / max(1, max(gray.shape))))
        upscaled = cv2.resize(gray, None, fx=factor, fy=factor, interpolation=cv2.INTER_CUBIC)
        candidates.append(("upscaled", upscaled))
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    candidates.append(("otsu", otsu))
    candidates.append(("inverted", cv2.bitwise_not(gray)))
    candidates.append(("autocontrast", np.array(ImageOps.autocontrast(rgb.convert("L")))))
    return candidates


def decode_qr_image(image_bytes: bytes) -> dict[str, Any]:
    image = open_image(image_bytes)
    meta = image_metadata(image, image_bytes)
    detector = cv2.QRCodeDetector()
    payloads: list[str] = []
    methods: list[str] = []

    for name, array in _candidate_arrays(image):
        try:
            ok, decoded, _points, _rects = detector.detectAndDecodeMulti(array)
            if ok and decoded:
                for value in decoded:
                    if value and value not in payloads:
                        payloads.append(value)
                        methods.append(f"opencv-multi:{name}")
        except cv2.error:
            pass
        if not payloads:
            try:
                value, _points, _rect = detector.detectAndDecode(array)
                if value and value not in payloads:
                    payloads.append(value)
                    methods.append(f"opencv-single:{name}")
            except cv2.error:
                pass
        if payloads:
            break

    if not payloads:
        try:  # optional dependency; not installed on every platform
            from pyzbar.pyzbar import decode as pyzbar_decode  # type: ignore

            for result in pyzbar_decode(image.convert("RGB")):
                value = result.data.decode("utf-8", errors="replace")
                if value and value not in payloads:
                    payloads.append(value)
                    methods.append("pyzbar")
        except Exception:
            pass

    return {
        "decoded": bool(payloads),
        "payloads": payloads,
        "count": len(payloads),
        "methods": methods,
        "image": meta,
        "caption": "",
        "warning": None if payloads else "No QR code could be decoded. Try a clearer, higher-resolution crop.",
    }


def parse_wifi_payload(payload: str) -> dict[str, Any]:
    body = payload[5:] if payload.upper().startswith("WIFI:") else payload
    fields: dict[str, str] = {}
    for part in body.split(";"):
        if ":" in part:
            key, value = part.split(":", 1)
            fields[key.upper()] = value.replace("\\;", ";").replace("\\,", ",")
    security = (fields.get("T") or "nopass").upper()
    password = fields.get("P")
    return {
        "ssid": fields.get("S"),
        "security": security,
        "hidden": (fields.get("H") or "").lower() == "true",
        "password_present": bool(password),
        "password_redacted": "***" if password else None,
        "risk": "open" if security in {"NOPASS", "NONE", ""} or security == "WEP" else "standard",
    }


def parse_vcard(payload: str) -> dict[str, Any]:
    fields: dict[str, str] = {}
    for line in payload.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.split(";", 1)[0].upper()
            if key in {"FN", "ORG", "TEL", "EMAIL", "URL", "NOTE", "TITLE"}:
                fields.setdefault(key, value.strip())
    return {"name": fields.get("FN"), "organization": fields.get("ORG"), "phone": fields.get("TEL"), "email": fields.get("EMAIL"), "url": fields.get("URL"), "note": truncate(fields.get("NOTE", ""), 300)}


def parse_crypto_payload(payload: str) -> dict[str, Any]:
    scheme, _, rest = payload.partition(":")
    address, _, query = rest.partition("?")
    params = {key.lower(): values[0] for key, values in parse_qs(query).items()}
    return {
        "asset": scheme.lower(),
        "address": address,
        "amount": params.get("amount"),
        "label": params.get("label"),
        "message": truncate(params.get("message", ""), 200),
    }


def inspect_payload(payload: str) -> dict[str, Any]:
    payload = (payload or "").strip()
    info: dict[str, Any] = {
        "payload": payload,
        "length": len(payload),
        "kind": "plain_text",
        "urls": [],
        "upi": None,
        "wifi": None,
        "vcard": None,
        "crypto": None,
        "warnings": [],
        "embedded_data": None,
    }
    if is_upi_uri(payload):
        upi = parse_upi_uri(payload)
        info["kind"] = "upi_payment"
        info["upi"] = upi.model_dump() if upi else None
        info["warnings"].append("This QR initiates a UPI payment from the scanner's account.")
        if upi and upi.warnings:
            info["warnings"].extend(upi.warnings)
        return info
    if payload.lower().startswith(("http://", "https://")):
        info["kind"] = "url"
        info["urls"] = [normalize_url(payload)]
        return info
    if _WIFI_RE.match(payload):
        wifi = parse_wifi_payload(payload)
        info["kind"] = "wifi"
        info["wifi"] = wifi
        if wifi["risk"] == "open":
            info["warnings"].append("This QR joins an open/unencrypted Wi-Fi network; traffic may be intercepted.")
        return info
    if _VCARD_RE.match(payload):
        info["kind"] = "vcard"
        info["vcard"] = parse_vcard(payload)
        return info
    if _CRYPTO_RE.match(payload):
        info["kind"] = "crypto_payment"
        info["crypto"] = parse_crypto_payload(payload)
        info["warnings"].append("This QR initiates a cryptocurrency transfer; on-chain payments are irreversible.")
        return info
    if _TEL_RE.match(payload) or _SMS_RE.match(payload):
        info["kind"] = "phone"
        return info
    if _MAILTO_RE.match(payload):
        info["kind"] = "email"
        return info
    if _GEO_RE.match(payload):
        info["kind"] = "location"
        return info
    if _OTPAUTH_RE.match(payload):
        info["kind"] = "otp_seed"
        info["warnings"].append("This QR contains a 2FA seed; do not share it with anyone.")
        return info

    urls = extract_urls(payload, limit=5)
    if urls:
        info["kind"] = "text_with_url"
        info["urls"] = [item.normalized for item in urls]
        return info
    if payload.startswith("{") or payload.startswith("["):
        info["kind"] = "structured_data"
        info["embedded_data"] = truncate(payload, 1000)
        return info
    if "%" in payload or len(payload) > 300:
        info["warnings"].append("Payload is unusually long or encoded; inspect it for embedded instructions.")
    return info
