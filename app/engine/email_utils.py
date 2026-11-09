"""Safe EML parsing, header forensics, HTML analysis and attachment triage.

The parser never executes attachments and never extracts archives to disk.  It
hashes, fingerprints and statically inspects content only.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup

from app.engine.brands import get_brand_registry
from app.engine.urls import extract_urls, registrable_domain
from app.engine.utils import compact_whitespace, dedupe, sha256_bytes, truncate
from app.engine.web import inspect_html
from app.schemas import Severity, SignalCategory

FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "yahoo.co.uk", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "aol.com", "protonmail.com", "proton.me",
    "icloud.com", "me.com", "mail.com", "gmx.com", "yandex.com", "zoho.com", "rediffmail.com",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".msi", ".msp", ".jar", ".apk", ".app", ".dmg", ".pkg", ".deb",
    ".rpm", ".iso", ".img", ".lnk", ".reg", ".cpl", ".dll", ".sys",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".xlam"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".ace"}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt", ".ods"}
MAX_ATTACHMENT_BYTES = 20 * 1024 * 1024
MAX_ATTACHMENTS = 25

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PUBLIC_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOUBLE_EXT_RE = re.compile(r"\.(?:pdf|docx?|xlsx?|pptx?|jpg|png|txt)\.(?:exe|scr|js|vbs|bat|cmd|apk|zip|html?)$", re.I)
_CMD_EXT_RE = re.compile(r"\.(?:exe|scr|js|vbs|bat|cmd|apk|html?)$", re.I)


def _header(msg: Message, name: str) -> str | None:
    value = msg.get(name)
    if value is None:
        return None
    return compact_whitespace(str(value))


def _headers(msg: Message, name: str) -> list[str]:
    return [compact_whitespace(str(value)) for value in (msg.get_all(name) or [])]


def _parse_address(value: str | None) -> tuple[str, str]:
    if not value:
        return "", ""
    pairs = getaddresses([value])
    if not pairs:
        return "", value
    display, address = pairs[0]
    return compact_whitespace(display or ""), (address or "").strip()


def _address_domain(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip(".").lower()


def _decode_idna(domain: str) -> str:
    try:
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return domain


def parse_received(value: str) -> dict[str, Any]:
    match_from = re.search(r"(?i)\bfrom\s+([^\s;()]+)", value)
    match_by = re.search(r"(?i)\bby\s+([^\s;()]+)", value)
    match_with = re.search(r"(?i)\bwith\s+([^\s;()]+)", value)
    match_for = re.search(r"(?i)\bfor\s+<?([^\s;>]+)", value)
    ip_match = _IPV4_RE.search(value)
    date_value = value.rsplit(";", 1)[-1].strip()
    parsed_date = None
    try:
        dt = parsedate_to_datetime(date_value)
        parsed_date = dt.isoformat() if dt else None
    except (TypeError, ValueError):
        parsed_date = None
    host = (match_from.group(1) if match_from else "").strip("[]").lower()
    ip = ip_match.group(0) if ip_match else ""
    private_ip = bool(
        ip
        and (
            ip.startswith(("10.", "127.", "192.168.", "169.254."))
            or re.match(r"^172\.(?:1[6-9]|2\d|3[01])\.", ip)
        )
    )
    return {
        "raw": truncate(value, 700),
        "from": host,
        "by": (match_by.group(1) if match_by else "").strip("[]").lower(),
        "with": match_with.group(1) if match_with else "",
        "for": match_for.group(1) if match_for else "",
        "ip": ip,
        "private_ip": private_ip,
        "date": parsed_date,
    }


def parse_authentication_results(values: list[str]) -> dict[str, Any]:
    combined = " ; ".join(values)
    summary: dict[str, Any] = {
        "spf": None,
        "dkim": [],
        "dmarc": None,
        "compauth": None,
        "raw": truncate(combined, 1500) if combined else "",
        "present": bool(combined),
    }
    for match in re.finditer(r"(?i)\b(spf|dkim|dmarc|compauth)\s*=\s*([a-z]+)", combined):
        mechanism, result = match.group(1).lower(), match.group(2).lower()
        if mechanism == "dkim":
            summary["dkim"].append(result)
        elif mechanism in {"spf", "dmarc", "compauth"}:
            if summary[mechanism] is None or result in {"fail", "softfail"}:
                summary[mechanism] = result
    return summary


def parse_dkim_signatures(values: list[str]) -> list[dict[str, Any]]:
    signatures = []
    for value in values:
        compact = value.replace("\r", "").replace("\n", " ")
        tags: dict[str, str] = {}
        for part in compact.split(";"):
            if "=" in part:
                key, val = part.split("=", 1)
                tags[key.strip().lower()] = val.strip()
        signatures.append(
            {
                "domain": tags.get("d"),
                "selector": tags.get("s"),
                "algorithm": tags.get("a"),
                "canonicalization": tags.get("c"),
                "signed_headers": truncate(tags.get("h", ""), 300),
                "body_hash_present": bool(tags.get("bh")),
                "signature_present": bool(tags.get("b")),
                "identity": tags.get("i"),
                "timestamp": tags.get("t"),
            }
        )
    return signatures


def _sniff_magic(payload: bytes) -> dict[str, Any]:
    if not payload:
        return {"family": "empty", "description": "Empty attachment"}
    head = payload[:16]
    if head.startswith(b"%PDF"):
        return {"family": "pdf", "description": "PDF document"}
    if head.startswith(b"PK\x03\x04"):
        return {"family": "zip", "description": "ZIP container (also used by Office OOXML files)"}
    if head.startswith(b"MZ"):
        return {"family": "pe", "description": "Windows PE executable"}
    if head.startswith(b"\x7fELF"):
        return {"family": "elf", "description": "Linux ELF executable"}
    if head.startswith(b"Rar!"):
        return {"family": "rar", "description": "RAR archive"}
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return {"family": "7z", "description": "7-Zip archive"}
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return {"family": "ole", "description": "OLE compound document (legacy Office/MSI)"}
    if head.lstrip().lower().startswith((b"<!doctype html", b"<html", b"<script")):
        return {"family": "html", "description": "HTML document"}
    if head.startswith(b"{\\rtf"):
        return {"family": "rtf", "description": "RTF document"}
    if head.startswith(b"\x1f\x8b"):
        return {"family": "gzip", "description": "Gzip archive"}
    if head.startswith(b"#!"):
        return {"family": "script", "description": "Script with shebang"}
    return {"family": "unknown", "description": "Unrecognised binary/text content"}


def _inspect_zip(payload: bytes) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    flags: list[str] = []
    encrypted = False
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            infos = archive.infolist()[:60]
            for info in infos:
                name = info.filename
                entries.append(
                    {
                        "name": truncate(name, 200),
                        "size": info.file_size,
                        "compressed_size": info.compress_size,
                        "encrypted": bool(info.flag_bits & 0x1),
                    }
                )
                if info.flag_bits & 0x1:
                    encrypted = True
                lower = name.lower()
                if lower.endswith("vbaproject.bin") or lower.endswith((".docm", ".xlsm", ".pptm")):
                    flags.append("contains_macros")
                if _CMD_EXT_RE.search(lower):
                    flags.append("contains_executable")
                if _DOUBLE_EXT_RE.search(lower):
                    flags.append("contains_double_extension")
            if any(
                entry["compressed_size"] > 0
                and entry["size"] / max(1, entry["compressed_size"]) > 100
                and entry["size"] > 10_000_000
                for entry in entries
            ):
                flags.append("possible_zip_bomb")
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        flags.append(f"zip_parse_error:{type(exc).__name__}")
    if encrypted:
        flags.append("encrypted_archive")
    return {
        "entries": entries,
        "entry_count": len(entries),
        "flags": dedupe(flags),
        "encrypted": encrypted,
    }


def _inspect_pdf(payload: bytes) -> dict[str, Any]:
    markers = {
        "javascript": payload.count(b"/JavaScript") + payload.count(b"/JS"),
        "open_action": payload.count(b"/OpenAction"),
        "embedded_file": payload.count(b"/EmbeddedFile"),
        "launch_action": payload.count(b"/Launch"),
        "uri_action": payload.count(b"/URI"),
        "encrypted": 1 if b"/Encrypt" in payload else 0,
    }
    urls = [item.normalized for item in extract_urls(payload.decode("latin-1", errors="ignore"), limit=5)]
    flags = []
    if markers["javascript"] or markers["open_action"] or markers["launch_action"]:
        flags.append("pdf_active_content")
    if markers["embedded_file"]:
        flags.append("pdf_embedded_file")
    if markers["encrypted"]:
        flags.append("pdf_encrypted")
    return {"markers": markers, "urls": urls, "flags": flags}


def _inspect_ole(payload: bytes) -> dict[str, Any]:
    upper = payload.upper()
    flags = []
    if b"VBA" in upper or b"VBAPROJECT" in upper:
        flags.append("contains_vba")
    if b"AUTOOPEN" in upper or b"DOCUMENT_OPEN" in upper or b"WORKBOOK_OPEN" in upper:
        flags.append("auto_exec_macro")
    if b"DDEAUTO" in upper or b"DDE " in upper:
        flags.append("dde_execution")
    return {"flags": dedupe(flags)}


def _inspect_attachment(part: Message, index: int) -> dict[str, Any]:
    filename = part.get_filename() or f"attachment-{index}"
    filename = truncate(str(filename), 250)
    content_type = part.get_content_type()
    try:
        payload = part.get_payload(decode=True) or b""
    except (ValueError, OSError):
        payload = b""
    original_size = len(payload)
    payload = payload[:MAX_ATTACHMENT_BYTES]
    extension = Path(filename).suffix.lower()
    magic = _sniff_magic(payload)
    flags: list[str] = []
    details: dict[str, Any] = {}

    if extension in EXECUTABLE_EXTENSIONS:
        flags.append("executable_extension")
    if extension in MACRO_EXTENSIONS:
        flags.append("macro_enabled_document")
    if extension in ARCHIVE_EXTENSIONS:
        flags.append("archive_attachment")
    if _DOUBLE_EXT_RE.search(filename):
        flags.append("double_extension")
    if magic["family"] in {"pe", "elf"} and extension not in EXECUTABLE_EXTENSIONS:
        flags.append("content_type_mismatch_executable")
    if magic["family"] == "html" and extension not in {".html", ".htm", ".xhtml"}:
        flags.append("content_type_mismatch_html")
    if magic["family"] == "pdf" and extension not in {".pdf", ""}:
        flags.append("content_type_mismatch_pdf")

    if magic["family"] == "zip":
        details["zip"] = _inspect_zip(payload)
        flags.extend(details["zip"]["flags"])
    if magic["family"] == "pdf":
        details["pdf"] = _inspect_pdf(payload)
        flags.extend(details["pdf"]["flags"])
    if magic["family"] == "ole":
        details["ole"] = _inspect_ole(payload)
        flags.extend(details["ole"]["flags"])
    if magic["family"] == "html":
        html = payload.decode("utf-8", errors="ignore")
        details["html"] = inspect_html(html, "https://attachment.invalid/")
        if details["html"].get("has_password_form"):
            flags.append("attachment_credential_form")
        if details["html"].get("external_form_targets"):
            flags.append("attachment_external_form")

    return {
        "index": index,
        "filename": filename,
        "content_type": content_type,
        "extension": extension,
        "size": original_size,
        "truncated": original_size > MAX_ATTACHMENT_BYTES,
        "sha256": sha256_bytes(payload),
        "md5": hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        "magic": magic,
        "flags": dedupe(flags),
        "details": details,
        "is_invoice_like": bool(
            re.search(r"(?i)(invoice|bill|receipt|payment|remittance|purchase\s*order)", filename)
        ),
        "is_document": extension in DOCUMENT_EXTENSIONS,
    }


def _visible_text_from_html(html: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    for element in soup(["script", "style", "head"]):
        element.decompose()
    return compact_whitespace(soup.get_text(" ", strip=True))


def parse_email(raw: bytes) -> dict[str, Any]:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    headers = {
        name: [_header(msg, name) or ""]
        for name in ("Subject", "Date", "From", "Sender", "Reply-To", "Return-Path", "To", "Cc", "Message-ID", "In-Reply-To", "References", "X-Mailer", "X-Originating-IP", "List-Unsubscribe")
        if msg.get(name)
    }
    received = [parse_received(value) for value in _headers(msg, "Received")]
    auth = parse_authentication_results(_headers(msg, "Authentication-Results"))
    received_spf = _header(msg, "Received-SPF")
    dkim_signatures = parse_dkim_signatures(_headers(msg, "DKIM-Signature"))

    from_display, from_address = _parse_address(_header(msg, "From"))
    reply_display, reply_address = _parse_address(_header(msg, "Reply-To"))
    return_path = (_header(msg, "Return-Path") or "").strip("<>")
    _sender_display, sender_address = _parse_address(_header(msg, "Sender"))
    from_domain = _address_domain(from_address)
    reply_domain = _address_domain(reply_address)
    return_domain = _address_domain(return_path)
    message_id = _header(msg, "Message-ID") or ""
    message_id_domain = ""
    id_match = re.search(r"@([^>\s]+)", message_id)
    if id_match:
        message_id_domain = id_match.group(1).lower().strip(".")

    text_body = ""
    html_body = ""
    attachments: list[dict[str, Any]] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        if disposition == "attachment" or part.get_filename():
            if len(attachments) < MAX_ATTACHMENTS:
                attachments.append(_inspect_attachment(part, len(attachments)))
            continue
        if content_type == "text/plain" and not text_body:
            try:
                text_body = part.get_content()
            except (LookupError, ValueError):
                payload = part.get_payload(decode=True) or b""
                text_body = payload.decode("utf-8", errors="replace")
        elif content_type == "text/html" and not html_body:
            try:
                html_body = part.get_content()
            except (LookupError, ValueError):
                payload = part.get_payload(decode=True) or b""
                html_body = payload.decode("utf-8", errors="replace")

    visible_html = _visible_text_from_html(html_body)
    body_text = compact_whitespace(text_body or visible_html)
    html_analysis = inspect_html(html_body, "https://message.invalid/") if html_body else {}

    all_url_text = "\n".join([body_text, html_body, " ".join(item.get("filename", "") for item in attachments)])
    urls = [
        {"url": item.normalized, "raw": item.raw}
        for item in extract_urls(all_url_text, limit=30)
    ]
    for anchor in (html_analysis.get("anchors") or []):
        if anchor.get("href", "").lower().startswith(("http://", "https://")):
            urls.append({"url": anchor["href"], "raw": anchor["href"]})
    deduped_urls: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    for item in urls:
        if item["url"] not in seen_urls:
            seen_urls.add(item["url"])
            deduped_urls.append(item)

    brands = get_brand_registry()
    flags: list[dict[str, Any]] = []

    def flag(
        identifier: str,
        label: str,
        detail: str,
        weight: int,
        severity: Severity,
        category: SignalCategory,
    ) -> None:
        flags.append(
            {
                "id": identifier,
                "label": label,
                "detail": detail,
                "weight": weight,
                "severity": severity.value,
                "category": category.value,
            }
        )

    if reply_address and from_address and reply_domain and from_domain and reply_domain != from_domain:
        same_site = registrable_domain(reply_domain) == registrable_domain(from_domain)
        if not same_site:
            flag(
                "reply_to_mismatch",
                "Reply-To points to a different domain",
                f"From domain '{from_domain}' but replies go to '{reply_domain}'. This is a common "
                "way to hide the real operator of a phishing or BEC email.",
                14,
                Severity.HIGH,
                SignalCategory.IDENTITY,
            )
    if return_path:
        if return_domain and from_domain and registrable_domain(return_domain) != registrable_domain(from_domain):
            flag(
                "return_path_mismatch",
                "Return-Path (envelope sender) mismatch",
                f"Envelope sender domain '{return_domain}' differs from the visible From domain '{from_domain}'.",
                10,
                Severity.MEDIUM,
                SignalCategory.IDENTITY,
            )
    if sender_address and from_address and sender_address.lower() != from_address.lower():
        flag(
            "sender_header_mismatch",
            "Sender header differs from From",
            f"Sender='{sender_address}' but From='{from_address}'.",
            8,
            Severity.MEDIUM,
            SignalCategory.IDENTITY,
        )
    if "@" in from_display and from_address and from_display.lower() not in from_address.lower():
        embedded = _parse_address(from_display)[1]
        if embedded and embedded.lower() != from_address.lower():
            flag(
                "display_name_embeds_other_address",
                "Display name contains a different email address",
                f"The visible name says '{from_display}' while the real address is '{from_address}'.",
                18,
                Severity.HIGH,
                SignalCategory.IDENTITY,
            )

    brand_mentions = brands.detect_mentions(f"{from_display} {_header(msg, 'Subject') or ''}")
    brand_match = brands.compare_domain(from_domain) if from_domain else None
    if brand_match and brand_match.kind != "official":
        flag(
            f"from_domain_{brand_match.kind}",
            "Sender domain resembles a trusted brand",
            brand_match.detail,
            26,
            Severity.HIGH,
            SignalCategory.IDENTITY,
        )
    elif brand_mentions and from_domain:
        official = any(brands.is_official(from_domain, brand) for brand in brand_mentions)
        if not official:
            names = ", ".join(brand["name"] for brand in brand_mentions[:3])
            flag(
                "display_brand_not_official_domain",
                "Brand name in display name, unofficial domain",
                f"The display name/subject references {names}, but '{from_domain}' is not an official domain.",
                20,
                Severity.HIGH,
                SignalCategory.IDENTITY,
            )

    if "xn--" in from_domain:
        flag(
            "punycode_sender",
            "Punycode sender domain",
            f"The sender domain '{from_domain}' decodes to '{_decode_idna(from_domain)}'.",
            16,
            Severity.HIGH,
            SignalCategory.OBFUSCATION,
        )

    if from_domain in FREE_MAIL_DOMAINS and brand_mentions:
        flag(
            "free_mail_brand_claim",
            "Brand claim from a free mailbox",
            f"A free mailbox ('{from_domain}') is used while the message claims to represent a brand or official body.",
            14,
            Severity.MEDIUM,
            SignalCategory.IDENTITY,
        )

    if message_id_domain and from_domain and registrable_domain(message_id_domain) != registrable_domain(from_domain):
        flag(
            "message_id_domain_mismatch",
            "Message-ID domain mismatch",
            f"Message-ID belongs to '{message_id_domain}', not the From domain '{from_domain}'.",
            6,
            Severity.LOW,
            SignalCategory.OBFUSCATION,
        )

    if auth["spf"] in {"fail", "softfail"}:
        flag(
            "spf_fail_header",
            f"SPF {auth['spf']} reported by receiving mail server",
            auth["raw"] or received_spf or "The receiving server reported SPF failure.",
            14 if auth["spf"] == "fail" else 8,
            Severity.HIGH if auth["spf"] == "fail" else Severity.MEDIUM,
            SignalCategory.AUTH,
        )
    if auth["dkim"] and all(result in {"fail", "invalid"} for result in auth["dkim"]):
        flag(
            "dkim_fail_header",
            "DKIM failed at the receiving server",
            "The receiver could not validate the DKIM signature(s).",
            10,
            Severity.MEDIUM,
            SignalCategory.AUTH,
        )
    if auth["dmarc"] == "fail":
        flag(
            "dmarc_fail_header",
            "DMARC failed",
            "The receiving server reported DMARC failure, meaning the visible From domain was not authenticated.",
            18,
            Severity.HIGH,
            SignalCategory.AUTH,
        )
    if not auth["present"] and not received_spf:
        flag(
            "no_auth_headers",
            "No authentication results in the email",
            "The message carries no Authentication-Results/Received-SPF headers. This can happen for "
            "locally supplied .eml files, so live DNS verification is required.",
            3,
            Severity.INFO,
            SignalCategory.AUTH,
        )

    public_hops = [hop for hop in received if hop["ip"] and not hop["private_ip"]]
    if any(hop["private_ip"] for hop in received):
        flag(
            "private_ip_in_received_chain",
            "Private address in Received chain",
            "At least one relay hop uses a private IP. Verify the chain if this email arrived from the internet.",
            6,
            Severity.LOW,
            SignalCategory.INFRASTRUCTURE,
        )
    if received and not public_hops:
        flag(
            "no_public_received_ip",
            "No public origin IP in Received chain",
            "The delivered message does not expose a public originating IP; live header analysis is limited.",
            5,
            Severity.INFO,
            SignalCategory.INFRASTRUCTURE,
        )

    html_flags = 0
    if html_analysis.get("has_password_form"):
        html_flags += 1
        flag(
            "html_password_form",
            "HTML body contains a password form",
            "A login form inside an email is a credential-harvesting pattern; legitimate senders link to their site.",
            22,
            Severity.HIGH,
            SignalCategory.CONTENT,
        )
    if int(html_analysis.get("visible_host_mismatches") or 0) > 0:
        html_flags += 1
        flag(
            "html_link_text_mismatch",
            "Displayed link differs from destination",
            "One or more visible link texts show a host different from the actual href.",
            16,
            Severity.HIGH,
            SignalCategory.CONTENT,
        )
    if html_analysis.get("hidden_texts"):
        html_flags += 1
        flag(
            "html_hidden_text",
            "Hidden text in HTML body",
            "The HTML contains hidden text, sometimes used to evade spam filters or mislead readers.",
            8,
            Severity.MEDIUM,
            SignalCategory.OBFUSCATION,
        )
    if html_analysis.get("external_form_targets"):
        html_flags += 1
        flag(
            "html_external_form",
            "Form posts to an external domain",
            "A form in the email submits data to a different registrable domain.",
            18,
            Severity.HIGH,
            SignalCategory.CONTENT,
        )
    if any(attachment["flags"] for attachment in attachments):
        risky = [
            f"{attachment['filename']} ({', '.join(attachment['flags'])})"
            for attachment in attachments
            if attachment["flags"]
        ]
        severe_flags = {
            flag_name
            for attachment in attachments
            for flag_name in attachment["flags"]
        } & {
            "executable_extension", "content_type_mismatch_executable", "contains_executable",
            "macro_enabled_document", "contains_macros", "auto_exec_macro", "dde_execution",
            "pdf_active_content", "attachment_credential_form", "double_extension",
        }
        flag(
            "risky_attachment",
            "Risky attachment content",
            "Static attachment triage: " + "; ".join(risky[:5]),
            24 if severe_flags else 10,
            Severity.HIGH if severe_flags else Severity.MEDIUM,
            SignalCategory.CONTENT,
        )
    if any(attachment.get("is_invoice_like") for attachment in attachments):
        flag(
            "invoice_attachment",
            "Invoice/payment-themed attachment",
            "At least one attachment is named like an invoice, receipt or remittance advice. Confirm payment "
            "changes through a known phone number, never by replying.",
            6,
            Severity.MEDIUM,
            SignalCategory.CONTENT,
        )

    subject = _header(msg, "Subject") or ""
    body_lower = body_text.lower()
    if re.search(r"(?i)\b(?:updated?\s+(?:bank|account|remittance)\s+(?:details?|information)|new\s+account\s+number|change\s+of\s+bank|wire\s+transfer|urgent\s+payment|payment\s+instruction)\b", body_lower):
        flag(
            "payment_change_request",
            "Payment/bank-detail change request",
            "The body asks for a payment or references changed banking details — a core Business Email Compromise pattern.",
            18,
            Severity.HIGH,
            SignalCategory.PAYMENT,
        )
    if re.search(r"(?i)\b(?:ceo|cfo|chairman|managing\s+director|founder|director)\b", f"{from_display} {body_lower[:500]}"):
        if from_domain in FREE_MAIL_DOMAINS or (brand_match and brand_match.kind != "official"):
            flag(
                "executive_impersonation",
                "Executive impersonation pattern",
                "An executive title is combined with a free-mail or lookalike sender domain.",
                16,
                Severity.HIGH,
                SignalCategory.IDENTITY,
            )
    if re.match(r"(?i)^\s*(re|fwd?|aw)\s*:", subject) and not _header(msg, "References"):
        flag(
            "fake_thread",
            "Reply/forward subject without thread references",
            "The subject claims to be part of a thread, but no References/In-Reply-To headers exist.",
            6,
            Severity.LOW,
            SignalCategory.OBFUSCATION,
        )

    urls_count = len(deduped_urls)
    return {
        "subject": subject,
        "date": _header(msg, "Date"),
        "from_display": from_display,
        "from_address": from_address,
        "from_domain": from_domain,
        "reply_to_display": reply_display,
        "reply_to_address": reply_address,
        "reply_to_domain": reply_domain,
        "return_path": return_path,
        "return_domain": return_domain,
        "sender_address": sender_address,
        "to": _headers(msg, "To"),
        "cc": _headers(msg, "Cc"),
        "message_id": message_id,
        "message_id_domain": message_id_domain,
        "headers": headers,
        "received": received,
        "auth_results": auth,
        "received_spf": received_spf,
        "dkim_signatures": dkim_signatures,
        "body_text": truncate(body_text, 25_000),
        "body_preview": truncate(body_text, 1200),
        "html_present": bool(html_body),
        "html_analysis": {
            key: value
            for key, value in html_analysis.items()
            if key not in {"anchors", "visible_text_excerpt", "image_sources", "link_urls"}
        },
        "urls": deduped_urls[:40],
        "attachments": attachments,
        "flags": flags,
        "raw_size": len(raw),
        "raw_sha256": sha256_bytes(raw),
        "has_list_unsubscribe": bool(_header(msg, "List-Unsubscribe")),
        "url_count": urls_count,
        "attachment_count": len(attachments),
    }
