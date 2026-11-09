"""Image preparation, perceptual hashing and optional local OCR."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from PIL import Image, ImageOps

from app.config import get_settings
from app.engine.qr_utils import image_metadata, open_image
from app.engine.urls import extract_urls
from app.engine.utils import sha256_bytes, truncate


def dhash(image: Image.Image, hash_size: int = 8) -> str:
    """Difference hash: robust to scaling/compression, useful for screenshot matching."""

    gray = image.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
    pixels = list(gray.getdata())
    bits = 0
    for row in range(hash_size):
        for column in range(hash_size):
            left = pixels[row * (hash_size + 1) + column]
            right = pixels[row * (hash_size + 1) + column + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return f"{bits:0{hash_size * hash_size // 4}x}"


def hamming_distance(left: str, right: str) -> int:
    if not left or not right or len(left) != len(right):
        return 64
    try:
        return bin(int(left, 16) ^ int(right, 16)).count("1")
    except ValueError:
        return 64


def prepare_for_vlm(image: Image.Image, max_dimension: int = 1600) -> tuple[bytes, str]:
    image = ImageOps.exif_transpose(image)
    if image.mode not in {"RGB", "L"}:
        background = Image.new("RGB", image.size, "white")
        if image.mode in {"RGBA", "LA"}:
            background.paste(image.convert("RGBA"), mask=image.convert("RGBA").split()[-1])
        else:
            background.paste(image.convert("RGB"))
        image = background
    else:
        image = image.convert("RGB")
    if max(image.size) > max_dimension:
        image.thumbnail((max_dimension, max_dimension), Image.Resampling.LANCZOS)
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=88, optimize=True)
    return buffer.getvalue(), "image/jpeg"


def basic_image_evidence(image_bytes: bytes) -> dict[str, Any]:
    image = open_image(image_bytes)
    meta = image_metadata(image, image_bytes)
    meta["dhash"] = dhash(image)
    meta["average_color"] = _average_color(image)
    return meta


def _average_color(image: Image.Image) -> str:
    small = image.convert("RGB").resize((1, 1), Image.Resampling.LANCZOS)
    red, green, blue = small.getpixel((0, 0))
    return f"#{red:02x}{green:02x}{blue:02x}"


def find_reference_image(slug: str) -> Path | None:
    directory = get_settings().brand_assets_dir
    if not directory.exists():
        return None
    for extension in (".png", ".jpg", ".jpeg", ".webp"):
        candidate = directory / f"{slug}{extension}"
        if candidate.exists():
            return candidate
    return None


def compare_with_reference(image_bytes: bytes, slug: str) -> dict[str, Any]:
    reference_path = find_reference_image(slug)
    if reference_path is None:
        return {
            "available": False,
            "reason": (
                f"No local reference image for '{slug}'. Add app/assets/brands/{slug}.png "
                "to enable perceptual comparison; the vision model still performs semantic comparison."
            ),
        }
    try:
        reference = Image.open(reference_path)
        reference.load()
        suspect = open_image(image_bytes)
    except Exception as exc:
        return {"available": False, "reason": f"Reference comparison failed: {exc}"}
    suspect_hash = dhash(suspect)
    reference_hash = dhash(reference)
    distance = hamming_distance(suspect_hash, reference_hash)
    similarity = round(max(0.0, 1 - distance / 64), 3)
    return {
        "available": True,
        "reference_path": reference_path.name,
        "suspect_dhash": suspect_hash,
        "reference_dhash": reference_hash,
        "hamming_distance": distance,
        "similarity": similarity,
        "interpretation": (
            "very similar layout" if distance <= 8
            else "broadly similar" if distance <= 16
            else "visually different"
        ),
    }


def try_local_ocr(image_bytes: bytes) -> dict[str, Any]:
    """Optional OCR. The primary OCR path is the vision-language model."""

    try:
        import pytesseract  # type: ignore

        image = open_image(image_bytes)
        text = pytesseract.image_to_string(image)
        return {"available": True, "engine": "tesseract", "text": truncate(text, 20_000)}
    except Exception as exc:
        return {
            "available": False,
            "engine": "tesseract",
            "error": f"Local OCR unavailable ({type(exc).__name__}); use the VLM OCR path.",
        }


def extract_screenshot_urls(ocr_text: str) -> list[str]:
    urls = [item.normalized for item in extract_urls(ocr_text or "", limit=8)]
    # OCR frequently mangles a URL bar; also surface bare host-like tokens.
    return list(dict.fromkeys(urls))


def image_sha256(image_bytes: bytes) -> str:
    return sha256_bytes(image_bytes)
