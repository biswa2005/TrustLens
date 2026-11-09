"""URL, domain and UPI static analysis.

Everything here is deterministic and explainable.  The language model never
invents infrastructure facts: it reasons over the signals produced by these
functions plus live DNS/TLS/threat-intelligence evidence.
"""

from __future__ import annotations

import html
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

import tldextract

from app.engine.brands import BrandRegistry, get_brand_registry, skeleton
from app.engine.utils import compact_whitespace, dedupe, signal_id, truncate
from app.schemas import Severity, SignalCategory, UPIInfo, URLSignal

_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_SCHEME_URL_RE = re.compile(r"(?i)\b(?:https?|hxxps?)://[^\s<>\"'`]+")
_WWW_URL_RE = re.compile(r"(?i)\bwww\.[^\s<>\"'`]+")
_BARE_DOMAIN_RE = re.compile(
    r"(?i)(?<![\w@.\-])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|in|co|io|me|ai|app|dev|xyz|top|site|online|info|biz|link|live|shop|"
    r"icu|ru|cn|tk|ml|ga|cf|gq|cc|ws|buzz|click|rest|fit|sbs|zip|mov|bank|pay|upi|"
    r"edu|gov|mil|uk|us|ca|au|de|fr|jp|sg|ae|sa|br|za|ng|ke|pk|bd|lk|np|ph|id|my|th|vn|"
    r"store|tech|cloud|support|help|finance|money|email|network|services|website|space|club|"
    r"pro|mobi|name|travel|jobs|law|blog|wiki|news|media|studio|design|art|fun|today|world|"
    r"life|group|agency|solutions|systems|digital|host|press|download|stream|review|date|win|"
    r"bid|trade|party|racing|loan|work|men|cam|quest|monster|best|bar|cyou|bond|sale|gift|"
    r"christmas|blackfriday))(:\d{2,5})?(?:/[^\s<>\"'`]*)?"
)
_TRAILING_PUNCT = ".,;:!?)]}>'\"`"

_HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "zip", "mov", "top", "xyz", "click", "icu", "sbs",
    "cfd", "buzz", "rest", "fit", "cam", "monster", "quest", "bar", "best", "cheap",
    "loan", "work", "men", "date", "review", "stream", "download", "party", "racing",
    "win", "bid", "trade", "country", "kim", "gdn", "cyou", "bond", "sale", "gift",
}
_MEDIUM_RISK_TLDS = {
    "online", "site", "info", "biz", "club", "space", "website", "press", "host",
    "support", "services", "email", "network", "live", "shop", "store", "tech",
}

_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "bit.do", "t.ly", "s.id", "lnkd.in", "tiny.cc",
    "shorte.st", "adf.ly", "bc.vc", "soo.gd", "clck.ru", "v.gd", "x.co", "me2.do",
    "short.gy", "1link.in", "t2m.io", "urlz.fr", "shrtco.de",
}

_LURE_WORDS = {
    "login", "signin", "sign-in", "verify", "verification", "secure", "security",
    "update", "kyc", "account", "wallet", "otp", "bank", "invoice", "payment",
    "refund", "gift", "bonus", "prize", "claim", "support", "helpdesk", "unlock",
    "recovery", "reactivate", "suspend", "limited", "alert", "billing", "delivery",
}

_DOWNLOAD_EXTENSIONS = {
    ".apk", ".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".zip",
    ".rar", ".7z", ".iso", ".img", ".dmg", ".pkg", ".lnk", ".hta", ".js",
}

_OPEN_REDIRECT_PARAMS = {
    "url", "redirect", "redirect_uri", "next", "target", "dest", "destination",
    "return", "returnurl", "return_url", "continue", "goto", "out", "link",
}

_COMMON_TLDS = {
    "com", "net", "org", "in", "co", "io", "me", "ai", "app", "dev", "xyz", "top",
    "site", "online", "info", "biz", "link", "live", "shop", "icu", "ru", "cn", "tk",
    "ml", "ga", "cf", "gq", "cc", "ws", "buzz", "click", "rest", "fit", "sbs", "zip",
    "mov", "bank", "pay", "upi", "edu", "gov", "mil", "uk", "us", "ca", "au", "de",
    "fr", "jp", "sg", "ae", "sa", "br", "za", "ng", "ke", "pk", "bd", "lk", "np",
    "ph", "id", "my", "th", "vn", "store", "tech", "cloud", "support", "help",
    "finance", "money", "email", "network", "services", "website", "space", "club",
    "pro", "mobi", "name", "travel", "jobs", "law", "blog", "wiki", "news", "media",
    "studio", "design", "art", "fun", "today", "world", "life", "group", "agency",
    "solutions", "systems", "digital", "host", "press", "download", "stream",
    "review", "date", "win", "bid", "trade", "party", "racing", "loan", "work", "men",
    "cam", "quest", "monster", "best", "bar", "cyou", "bond", "sale", "gift",
}

_UPI_SCHEMES = {"upi", "phonepe", "tez", "gpay", "paytmmp", "bhim", "amazonpay", "credpay"}
_UPI_HANDLES = {
    "ybl", "ibl", "axl", "apl", "paytm", "okaxis", "okhdfcbank", "okicici", "oksbi",
    "upi", "sbi", "hdfcbank", "icici", "axisb", "kotak", "yesbank", "idfcbank",
    "airtel", "freecharge", "jupiteraxis", "naviaxis", "slice", "fi", "federal",
    "barodampay", "cnrb", "pnb", "unionbank", "indus", "rbl", "dbs", "hsbc",
    "waaxis", "wahdfcbank", "waicici", "wasbi", "superyes", "abfspay", "timecosmos",
    "ngpay", "shriramhdfcbank", "navi", "tapicici", "ffcare", "aubank", "bandhan",
    "jkb", "kbl", "tjsb", "equitas", "sib", "ucobank", "utkarsh", "jkbpay",
}
_BRAND_HANDLES = {
    "paytm": {"paytm"},
    "phonepe": {"ybl", "ibl", "axl"},
    "googlepay": {"okaxis", "okhdfcbank", "okicici", "oksbi"},
    "amazon": {"apl"},
    "amazonpay": {"apl"},
    "bhim": {"upi"},
}
_VPA_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]{1,60}@[a-zA-Z][a-zA-Z0-9]{1,30}$")
_VPA_HINT_RE = re.compile(r"\b([a-zA-Z0-9][a-zA-Z0-9._\-]{1,60}@[a-zA-Z][a-zA-Z0-9]{1,30})\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s\-]?)?[6-9]\d{9}(?!\d)")
_IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
_AMOUNT_RE = re.compile(r"(?i)(?:₹|rs\.?|inr)\s*([0-9][0-9,.]*)(?:\s*(lakh|crore|k))?")
_EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b")


@dataclass
class ExtractedURL:
    raw: str
    normalized: str


@dataclass
class StaticURLResult:
    url: str
    normalized_url: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    decoded_host: str = ""
    domain: str = ""
    suffix: str = ""
    registered_domain: str = ""
    is_ip_literal: bool = False
    is_punycode: bool = False
    is_shortener: bool = False
    brand_match: str | None = None
    signals: list[URLSignal] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "normalized_url": self.normalized_url,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "query": truncate(self.query, 500),
            "decoded_host": self.decoded_host,
            "domain": self.domain,
            "suffix": self.suffix,
            "registered_domain": self.registered_domain,
            "is_ip_literal": self.is_ip_literal,
            "is_punycode": self.is_punycode,
            "is_shortener": self.is_shortener,
            "brand_match": self.brand_match,
            "signals": [signal.model_dump(mode="json") for signal in self.signals],
            "notes": self.notes,
        }


def refang(text: str) -> str:
    text = text or ""
    text = re.sub(r"(?i)\bhxxps\b", "https", text)
    text = re.sub(r"(?i)\bhxxp\b", "http", text)
    text = re.sub(r"(?i)\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", text)
    text = re.sub(r"(?i)\[:]", ":", text)
    text = re.sub(r"(?i)\[/\]", "/", text)
    text = re.sub(r"(?i)\[@\]", "@", text)
    return text


def _looks_like_domain(value: str) -> bool:
    ext = _EXTRACTOR(value)
    if not ext.domain or not ext.suffix:
        return False
    # Public suffixes are often multi-label ("co.in", "com.au", "co.uk"); only
    # the final label needs to be an accepted TLD.  Gating on the whole suffix
    # silently dropped legitimate links such as https://offers.sbi.co.in.
    labels = ext.suffix.lower().split(".")
    return labels[-1] in _COMMON_TLDS


def _strip_url(raw: str) -> str:
    value = html.unescape(raw.strip())
    value = value.rstrip(_TRAILING_PUNCT)
    # Remove an unmatched closing parenthesis while preserving real ones.
    while value.endswith(")") and value.count("(") < value.count(")"):
        value = value[:-1].rstrip(_TRAILING_PUNCT)
    return value


def normalize_url(raw: str) -> str:
    value = refang(_strip_url(raw))
    if value.lower().startswith("//"):
        value = "https:" + value
    if not re.match(r"(?i)^[a-z][a-z0-9+.\-]*://", value):
        value = "http://" + value
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    host = (parts.hostname or "").lower()
    if not host:
        return value
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = host
    netloc = ascii_host
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    if parts.username or parts.password:
        credentials = ""
        if parts.username:
            credentials += parts.username
        if parts.password:
            credentials += ":***"
        netloc = f"{credentials}@{netloc}"
    path = parts.path or ""
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def _resource_key(url: str) -> str:
    """Scheme-agnostic identity of a URL (host + port + path + query).

    ``https://example.com/a`` and ``http://example.com/a`` address the same
    resource; only one of them may be investigated when both arise from the
    same piece of text.
    """
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return url.lower()
    return f"{host}{port}{parts.path}?{parts.query}".lower()


def extract_urls(text: str, *, include_bare: bool = True, limit: int = 25) -> list[ExtractedURL]:
    if not text:
        return []
    refanged = refang(text)
    # (candidate, explicitly_schemed): the scheme/www patterns run first, so an
    # explicit URL always wins over a bare-domain match for the same resource.
    found: list[tuple[str, bool]] = []
    for pattern in (_SCHEME_URL_RE, _WWW_URL_RE):
        found.extend((match.group(0), True) for match in pattern.finditer(refanged))
    if include_bare:
        found.extend((match.group(0), False) for match in _BARE_DOMAIN_RE.finditer(refanged))
    results: list[ExtractedURL] = []
    seen_full: set[str] = set()
    seen_resource: set[str] = set()
    for raw, explicit in found:
        cleaned = _strip_url(raw)
        normalized = normalize_url(cleaned)
        try:
            host = urlsplit(normalized).hostname or ""
        except ValueError:
            continue
        if not host or "." not in host:
            continue
        if not _looks_like_domain(host) and not _is_ip(host):
            continue
        full_key = normalized.lower()
        resource_key = _resource_key(normalized)
        if explicit:
            if full_key in seen_full or resource_key in seen_resource:
                continue
        else:
            # Without this check a bare match of a substring that already had a
            # scheme would be re-added as "http://<same resource>" by
            # normalize_url, causing a duplicate investigation that produced two
            # contradictory findings for one host.
            if resource_key in seen_resource:
                continue
        seen_full.add(full_key)
        seen_resource.add(resource_key)
        results.append(ExtractedURL(raw=cleaned, normalized=normalized))
        if len(results) >= limit:
            break
    return results


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_upi_uri(value: str) -> bool:
    lowered = (value or "").lower()
    return lowered.startswith("upi:") or any(
        lowered.startswith(f"{scheme}:") for scheme in _UPI_SCHEMES - {"upi"}
    ) or lowered.startswith("intent://pay")


def parse_upi_uri(raw: str) -> UPIInfo | None:
    if not is_upi_uri(raw):
        return None
    value = raw.strip()
    query = ""
    scheme = "upi"
    if value.lower().startswith("intent://"):
        fragments = value.split("#", 1)
        query = fragments[0].split("?", 1)[1] if "?" in fragments[0] else ""
        scheme_match = re.search(r"(?i)scheme=([a-z]+)", value)
        if scheme_match:
            scheme = scheme_match.group(1).lower()
    else:
        parts = urlsplit(value)
        scheme = (parts.scheme or "upi").lower()
        query = parts.query
        if not query and "?" in value:
            query = value.split("?", 1)[1]
    params = {key.lower(): values[0] for key, values in parse_qs(query, keep_blank_values=True).items()}
    vpa = params.get("pa") or params.get("vpa") or params.get("payeevpa")
    payee_name = params.get("pn") or params.get("payeename")
    amount = params.get("am") or params.get("amount")
    currency = params.get("cu") or params.get("currency")
    note = params.get("tn") or params.get("note") or params.get("transactionnote")
    handle = vpa.split("@", 1)[1].lower() if vpa and "@" in vpa else None
    known = bool(handle and handle in _UPI_HANDLES)
    warnings: list[str] = []
    if not vpa:
        warnings.append("UPI URI has no payee address (pa) — the destination is unidentified.")
    elif not _VPA_RE.match(vpa):
        warnings.append(f"Payee address '{vpa}' does not match the expected UPI VPA syntax.")
    if handle and not known:
        warnings.append(
            f"Payee handle '@{handle}' is not in the known Indian PSP/bank handle set; verify it independently."
        )
    if not payee_name:
        warnings.append("No payee name (pn) is present, so the recipient cannot be sanity-checked.")
    if amount:
        try:
            if float(amount.replace(",", "")) <= 0:
                warnings.append("Payment amount is zero or invalid.")
        except ValueError:
            warnings.append(f"Payment amount '{amount}' is not numeric.")
    else:
        warnings.append(
            "No amount is fixed in the URI; the payment app will ask the user to enter one."
        )
    if currency and currency.upper() != "INR":
        warnings.append(f"Currency is {currency}, not INR — unexpected for an Indian UPI request.")
    note_lower = (note or "").lower()
    name_lower = (payee_name or "").lower()
    for word in ("receive", "refund", "cashback", "prize", "reward", "lottery", "win"):
        if word in note_lower or word in name_lower:
            warnings.append(
                f"The payee/note text says '{word}'. A UPI QR/URI always *debits* the scanner; "
                "promises of receiving money are a common fraud pattern."
            )
            break
    if payee_name:
        for brand_key, handles in _BRAND_HANDLES.items():
            if brand_key in name_lower and handle and handle not in handles:
                warnings.append(
                    f"Payee name mentions {brand_key} but the handle '@{handle}' is not one of its "
                    "known payment handles."
                )
                break
    return UPIInfo(
        raw=raw,
        scheme=scheme,
        payee_vpa=vpa,
        payee_name=payee_name,
        amount=amount,
        currency=currency,
        transaction_note=note,
        merchant_code=params.get("mc"),
        transaction_ref=params.get("tr") or params.get("txnref"),
        handle=handle,
        is_known_handle=known,
        warnings=dedupe(warnings),
    )


def extract_upi_ids(text: str) -> list[str]:
    candidates = []
    for match in _VPA_HINT_RE.finditer(text or ""):
        value = match.group(1)
        if "@" not in value:
            continue
        handle = value.split("@", 1)[1].lower()
        if handle in _UPI_HANDLES:
            candidates.append(value)
    return dedupe(candidates)


def extract_entities(text: str) -> dict[str, list[str]]:
    text = text or ""
    amounts = []
    for match in _AMOUNT_RE.finditer(text):
        suffix = f" {match.group(2)}" if match.group(2) else ""
        amounts.append(f"{match.group(1)}{suffix}".replace(",", ""))
    return {
        "urls": [item.normalized for item in extract_urls(text)],
        "upi_ids": extract_upi_ids(text),
        "phone_numbers": dedupe(_PHONE_RE.findall(text)),
        "emails": dedupe(match.group(0) for match in _EMAIL_RE.finditer(text)),
        "ifsc_codes": dedupe(_IFSC_RE.findall(text)),
        "amounts": dedupe(amounts),
    }


def _signal(
    identifier: str,
    label: str,
    detail: str,
    *,
    weight: int,
    severity: Severity,
    category: SignalCategory = SignalCategory.LINK,
) -> URLSignal:
    return URLSignal(
        id=signal_id("url", identifier, detail),
        label=label,
        detail=detail,
        severity=severity,
        weight=weight,
        category=category,
    )


def analyze_url_static(
    url: str,
    *,
    brands: BrandRegistry | None = None,
) -> StaticURLResult:
    brands = brands or get_brand_registry()
    normalized = normalize_url(url)
    try:
        parts = urlsplit(normalized)
    except ValueError:
        parts = urlsplit("http://invalid.invalid")
    host = (parts.hostname or "").lower()
    port = parts.port
    scheme = parts.scheme.lower()
    path = parts.path or ""
    query = parts.query or ""
    decoded_host = host
    is_punycode = "xn--" in host
    if is_punycode:
        try:
            decoded_host = host.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            decoded_host = host
    ext = _EXTRACTOR(decoded_host)
    registered = ".".join(part for part in (ext.domain, ext.suffix) if part)
    is_ip = _is_ip(host)

    result = StaticURLResult(
        url=url,
        normalized_url=normalized,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query=query,
        decoded_host=decoded_host,
        domain=ext.domain,
        suffix=ext.suffix,
        registered_domain=registered,
        is_ip_literal=is_ip,
        is_punycode=is_punycode,
    )

    if is_ip:
        result.signals.append(
            _signal(
                "ip_literal",
                "IP-address host",
                f"The URL uses the raw IP address {host} instead of a branded domain.",
                weight=15,
                severity=Severity.MEDIUM,
            )
        )
    if is_punycode or (decoded_host and decoded_host != host):
        result.signals.append(
            _signal(
                "punycode",
                "Internationalised / punycode host",
                f"Host decodes to '{decoded_host}'. Verify it visually; punycode is often used for lookalikes.",
                weight=15,
                severity=Severity.HIGH,
                category=SignalCategory.OBFUSCATION,
            )
        )
        if any(ord(char) > 127 for char in decoded_host):
            result.signals.append(
                _signal(
                    "mixed_script",
                    "Non-Latin characters in hostname",
                    "The hostname contains non-ASCII characters that may imitate Latin letters.",
                    weight=12,
                    severity=Severity.HIGH,
                    category=SignalCategory.OBFUSCATION,
                )
            )

    if scheme == "http":
        result.signals.append(
            _signal(
                "no_tls",
                "Unencrypted HTTP",
                "The link does not use HTTPS, so credentials and content can be altered in transit.",
                weight=7,
                severity=Severity.MEDIUM,
            )
        )

    if parts.username or parts.password:
        result.signals.append(
            _signal(
                "userinfo_trick",
                "Credentials embedded in URL",
                "The URL contains a user-info component before the host. Attackers use this to make "
                "the visible text look like a trusted domain while the real host is different.",
                weight=22,
                severity=Severity.HIGH,
                category=SignalCategory.OBFUSCATION,
            )
        )

    if registered in _SHORTENERS:
        result.is_shortener = True
        result.signals.append(
            _signal(
                "shortener",
                "URL shortener",
                f"'{registered}' hides the final destination. Expand it before trusting the link.",
                weight=10,
                severity=Severity.MEDIUM,
                category=SignalCategory.OBFUSCATION,
            )
        )

    suffix = (ext.suffix or "").split(".")[-1].lower()
    if suffix in _HIGH_RISK_TLDS:
        result.signals.append(
            _signal(
                "high_risk_tld",
                "High-abuse top-level domain",
                f".{suffix} is heavily abused for throwaway phishing infrastructure.",
                weight=10 if suffix not in {"zip", "mov"} else 13,
                severity=Severity.MEDIUM,
            )
        )
    elif suffix in _MEDIUM_RISK_TLDS:
        result.signals.append(
            _signal(
                "cheap_tld",
                "Low-cost / frequently abused TLD",
                f".{suffix} is inexpensive and frequently used in short-lived scam campaigns.",
                weight=4,
                severity=Severity.LOW,
            )
        )

    label = ext.domain or ""
    subdomain = decoded_host[: -(len(registered) + 1)] if registered and decoded_host.endswith(registered) else ""
    sub_labels = [part for part in subdomain.split(".") if part]
    if len(sub_labels) >= 3:
        result.signals.append(
            _signal(
                "many_subdomains",
                "Deep subdomain nesting",
                f"{len(sub_labels)} subdomain labels precede '{registered}', a common way to bury "
                "the real domain.",
                weight=6,
                severity=Severity.LOW,
            )
        )
    if len(label) >= 30:
        result.signals.append(
            _signal(
                "long_domain",
                "Unusually long domain label",
                f"The registrable label is {len(label)} characters long.",
                weight=3,
                severity=Severity.LOW,
            )
        )
    if label.count("-") >= 3:
        result.signals.append(
            _signal(
                "many_hyphens",
                "Hyphen-stuffed domain",
                f"'{label}' contains {label.count('-')} hyphens, typical of keyword-stuffed phishing hosts.",
                weight=5,
                severity=Severity.LOW,
            )
        )
    if len(normalized) > 180:
        result.signals.append(
            _signal(
                "long_url",
                "Very long URL",
                f"The URL is {len(normalized)} characters long, which can obscure the true host.",
                weight=3,
                severity=Severity.LOW,
            )
        )

    brand_match = brands.compare_domain(host)
    if brand_match and brand_match.kind != "official":
        result.brand_match = brand_match.label
        weight = {
            "brand_in_subdomain": 28,
            "homoglyph": 24,
            "typosquat": 22,
            "keyword_combo": 23,
        }.get(brand_match.kind, 18)
        result.signals.append(
            _signal(
                f"brand_{brand_match.kind}",
                "Possible brand impersonation",
                brand_match.detail,
                weight=weight,
                severity=Severity.HIGH,
                category=SignalCategory.IDENTITY,
            )
        )

    lure_hits = {
        word
        for word in _LURE_WORDS
        if re.search(rf"(?i)(?<![a-z]){re.escape(word)}(?![a-z])", f"{path} {query} {subdomain}")
    }
    if lure_hits:
        result.signals.append(
            _signal(
                "credential_lure_path",
                "Credential/urgency keywords in URL",
                "The path or subdomain contains: " + ", ".join(sorted(lure_hits)[:6]),
                weight=min(12, 4 + 2 * len(lure_hits)),
                severity=Severity.MEDIUM,
                category=SignalCategory.CONTENT,
            )
        )

    lower_path = unquote(path).lower()
    if any(lower_path.endswith(extension) for extension in _DOWNLOAD_EXTENSIONS):
        result.signals.append(
            _signal(
                "direct_download",
                "Direct executable/archive download",
                f"The URL points directly at a '{lower_path.rsplit('.', 1)[-1]}' file.",
                weight=12,
                severity=Severity.HIGH,
                category=SignalCategory.CONTENT,
            )
        )

    if any(key in {key.lower() for key in parse_qs(query)} for key in _OPEN_REDIRECT_PARAMS):
        decoded_target = unquote(query)
        if "http" in decoded_target.lower():
            result.signals.append(
                _signal(
                    "open_redirect",
                    "Possible open-redirect parameter",
                    "A query parameter contains another absolute URL, which may bounce the user to "
                    "a different site after the trusted domain loads.",
                    weight=8,
                    severity=Severity.MEDIUM,
                )
            )

    if re.search(r"%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}", normalized, re.I):
        result.signals.append(
            _signal(
                "heavy_encoding",
                "Heavily percent-encoded URL",
                "Multiple encoded layers can hide the true destination from casual inspection.",
                weight=5,
                severity=Severity.LOW,
                category=SignalCategory.OBFUSCATION,
            )
        )

    if port and port not in {80, 443}:
        result.signals.append(
            _signal(
                "nonstandard_port",
                "Non-standard port",
                f"The URL connects on port {port} rather than 80/443.",
                weight=5,
                severity=Severity.MEDIUM,
            )
        )

    if re.search(r"(?i)\.(pdf|docx?|xlsx?|html?)\.(exe|scr|js|vbs|apk|zip|html?)$", lower_path):
        result.signals.append(
            _signal(
                "double_extension",
                "Double file extension",
                "The filename uses a decoy document extension before the real executable extension.",
                weight=14,
                severity=Severity.HIGH,
                category=SignalCategory.OBFUSCATION,
            )
        )

    # Deduplicate signals by id
    unique: dict[str, URLSignal] = {}
    for item in result.signals:
        unique[item.id] = item
    result.signals = sorted(unique.values(), key=lambda item: item.weight, reverse=True)
    return result


def registrable_domain(host: str) -> str:
    ext = _EXTRACTOR(host)
    return ".".join(part for part in (ext.domain, ext.suffix) if part)


def same_site(left: str, right: str) -> bool:
    return registrable_domain(left).lower() == registrable_domain(right).lower() != ""


def host_from_text_url(value: str) -> str:
    try:
        return (urlsplit(normalize_url(value)).hostname or "").lower()
    except ValueError:
        return ""


def url_display(value: str) -> str:
    return compact_whitespace(truncate(refang(value), 300))


__all__ = [
    "ExtractedURL",
    "StaticURLResult",
    "analyze_url_static",
    "extract_entities",
    "extract_upi_ids",
    "extract_urls",
    "host_from_text_url",
    "is_upi_uri",
    "normalize_url",
    "parse_upi_uri",
    "refang",
    "registrable_domain",
    "same_site",
    "skeleton",
]
