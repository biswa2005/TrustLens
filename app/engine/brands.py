"""Curated brand registry plus lookalike / homoglyph analysis.

This is a reference database, not a trained classifier.  Impersonation claims
are always phrased as *possible* impersonation and are grounded in an explicit
string-distance, homoglyph or domain-mismatch observation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import tldextract

from app.config import get_settings

_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ї": "i", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "ɡ": "g", "ԛ": "q", "ԝ": "w", "ѵ": "v", "ј": "j",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "γ": "y", "η": "n", "μ": "u", "σ": "o",
    # digit / symbol substitutions
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s",
}

_BRAND_SPLIT_RE = re.compile(r"[-_.\s]+")
_WORD_RE = re.compile(r"[^\W_]+", re.UNICODE)


@dataclass(frozen=True)
class BrandMatch:
    brand: dict[str, Any]
    kind: str  # brand_in_subdomain | typosquat | homoglyph | keyword_combo | official
    label: str
    detail: str
    confidence: float


def skeleton(value: str) -> str:
    value = value.lower()
    return "".join(_CONFUSABLES.get(char, char) for char in value)


def levenshtein(left: str, right: str, max_distance: int = 4) -> int:
    if left == right:
        return 0
    if abs(len(left) - len(right)) > max_distance:
        return max_distance + 1
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            cost = 0 if left_char == right_char else 1
            current.append(min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


def _allowed_distance(brand_token: str) -> int:
    length = len(brand_token)
    if length <= 4:
        return 0
    if length <= 6:
        return 1
    if length <= 10:
        return 2
    return 3


class BrandRegistry:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or get_settings().brand_registry_path
        self.brands: list[dict[str, Any]] = []
        self._by_domain: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {"brands": []}
        self.brands = payload.get("brands", [])
        for brand in self.brands:
            for domain in brand.get("domains", []):
                self._by_domain[domain.lower().strip(".")] = brand

    def get(self, name_or_slug: str) -> dict[str, Any] | None:
        needle = (name_or_slug or "").lower().strip()
        if not needle:
            return None
        for brand in self.brands:
            if needle in {brand["name"].lower(), brand.get("slug", "").lower()}:
                return brand
            if needle in [alias.lower() for alias in brand.get("aliases", [])]:
                return brand
        return None

    def by_domain(self, host: str) -> dict[str, Any] | None:
        host = (host or "").lower().strip(".")
        for domain, brand in self._by_domain.items():
            if host == domain or host.endswith("." + domain):
                return brand
        return None

    def is_official(self, host: str, brand: dict[str, Any] | None = None) -> bool:
        if not host:
            return False
        matched = self.by_domain(host)
        if matched is None:
            return False
        return brand is None or matched.get("slug") == brand.get("slug")

    def detect_mentions(self, text: str, limit: int = 6) -> list[dict[str, Any]]:
        lowered = (text or "").lower()
        found: list[dict[str, Any]] = []
        for brand in self.brands:
            tokens = [brand["name"], *brand.get("aliases", [])]
            for token in tokens:
                token = token.strip().lower()
                if len(token) < 3:
                    continue
                if re.search(rf"(?<![\w]){re.escape(token)}(?![\w])", lowered):
                    found.append(brand)
                    break
        return found[:limit]

    def compare_domain(self, host: str) -> BrandMatch | None:
        """Return a possible impersonation observation for a host, if any."""

        host = (host or "").lower().strip(".")
        if not host:
            return None
        official = self.by_domain(host)
        if official:
            return BrandMatch(
                brand=official,
                kind="official",
                label=official["name"],
                detail=f"{host} belongs to the official {official['name']} domain set.",
                confidence=0.99,
            )

        try:
            decoded = host.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            decoded = host
        ext = _EXTRACTOR(decoded)
        registrable = ".".join(part for part in (ext.domain, ext.suffix) if part)
        labels = [label for label in decoded.split(".") if label not in {"www", "m", "web"}]
        candidates = set()
        for label in labels:
            candidates.update(part for part in _BRAND_SPLIT_RE.split(label) if part)
        if ext.domain:
            candidates.add(ext.domain)

        normalized_candidates = {skeleton(candidate) for candidate in candidates}

        for brand in self.brands:
            official_domains = brand.get("domains", [])
            if any(
                decoded == domain or decoded.endswith("." + domain)
                for domain in official_domains
            ):
                return BrandMatch(
                    brand=brand,
                    kind="official",
                    label=brand["name"],
                    detail=f"{decoded} is an official {brand['name']} domain.",
                    confidence=0.99,
                )

            tokens = {brand.get("slug", ""), *[alias.replace(" ", "") for alias in brand.get("aliases", [])]}
            tokens = {skeleton(token) for token in tokens if len(token) >= 4}

            # e.g. paypal.com.verify-account.xyz
            for domain in official_domains:
                if f".{domain}." in f".{decoded}.":
                    return BrandMatch(
                        brand=brand,
                        kind="brand_in_subdomain",
                        label=brand["name"],
                        detail=(
                            f"The string '{domain}' appears inside the hostname, but the real "
                            f"registrable domain is '{registrable}' — a classic brand-in-subdomain trick."
                        ),
                        confidence=0.95,
                    )

            for candidate in normalized_candidates:
                if candidate in tokens and candidate != "www":
                    if registrable and registrable not in official_domains:
                        return BrandMatch(
                            brand=brand,
                            kind="keyword_combo",
                            label=brand["name"],
                            detail=(
                                f"Hostname contains the brand token '{candidate}' but is registered "
                                f"on '{registrable}', not an official {brand['name']} domain."
                            ),
                            confidence=0.88,
                        )
                for token in tokens:
                    if len(candidate) < 4 or len(token) < 4:
                        continue
                    threshold = _allowed_distance(token)
                    if threshold == 0:
                        continue
                    distance = levenshtein(candidate, token, threshold)
                    if 0 < distance <= threshold:
                        kind = "homoglyph" if skeleton(candidate) == token else "typosquat"
                        return BrandMatch(
                            brand=brand,
                            kind=kind,
                            label=brand["name"],
                            detail=(
                                f"'{candidate}' is {distance} edit(s) away from the {brand['name']} "
                                f"token '{token}' (registrable domain: '{registrable}')."
                            ),
                            confidence=0.78 if kind == "homoglyph" else 0.7,
                        )
        return None


@lru_cache(maxsize=1)
def get_brand_registry() -> BrandRegistry:
    return BrandRegistry()
