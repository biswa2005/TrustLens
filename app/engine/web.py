"""Non-executing inspection of suspect web pages.

Scripts are never executed.  We only parse server-returned HTML to answer
investigator questions: What does the page claim to be?  Does it ask for
credentials?  Where do its forms post?  Does visible link text disagree with
the actual href?
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from app.engine.net import NetworkDisabled, SafeHttpClient, UnsafeTarget
from app.engine.urls import extract_urls, registrable_domain
from app.engine.utils import compact_whitespace, truncate

_CREDENTIAL_INPUT_TYPES = {"password", "email", "tel"}
_CREDENTIAL_NAME_HINTS = {
    "password", "passwd", "pwd", "otp", "pin", "cvv", "card", "account", "userid",
    "user", "email", "mobile", "phone", "aadhaar", "pan", "upi", "mpin", "dob",
}
_HIDDEN_STYLE_RE = re.compile(
    r"(?i)(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|"
    r"color\s*:\s*(?:#fff(?:fff)?|white)|height\s*:\s*0|opacity\s*:\s*0)"
)


def _form_summary(form: Any, base_url: str) -> dict[str, Any]:
    inputs: list[dict[str, str]] = []
    for field in form.find_all(["input", "select", "textarea"]):
        field_type = (field.get("type") or field.name or "text").lower()
        name = (field.get("name") or field.get("id") or "").strip()
        if not name and field_type == "hidden":
            continue
        inputs.append(
            {
                "type": field_type[:30],
                "name": name[:80],
                "placeholder": truncate(field.get("placeholder") or "", 80),
                "autocomplete": (field.get("autocomplete") or "")[:40],
            }
        )
    action = form.get("action") or ""
    method = (form.get("method") or "get").lower()
    action_url = urljoin(base_url, action) if action else base_url
    password_fields = sum(1 for item in inputs if item["type"] == "password")
    credential_fields = [
        item
        for item in inputs
        if item["type"] in _CREDENTIAL_INPUT_TYPES
        or any(hint in item["name"].lower() for hint in _CREDENTIAL_NAME_HINTS)
    ]
    return {
        "action": truncate(action_url, 500),
        "action_host": (urlsplit(action_url).hostname or "").lower(),
        "method": method,
        "inputs": inputs[:30],
        "password_fields": password_fields,
        "credential_fields": credential_fields[:20],
        "has_otp_field": any(
            "otp" in item["name"].lower() or "otp" in item["placeholder"].lower()
            for item in inputs
        ),
        "has_card_field": any(
            "card" in item["name"].lower() or "cvv" in item["name"].lower() for item in inputs
        ),
        "has_upi_pin_field": any("upi" in item["name"].lower() for item in inputs),
    }


def inspect_html(html: str, base_url: str) -> dict[str, Any]:
    soup = BeautifulSoup(html or "", "html.parser")
    title = compact_whitespace(soup.title.get_text(" ", strip=True))[:200] if soup.title else ""
    meta_description = ""
    meta = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
    if meta and meta.get("content"):
        meta_description = truncate(meta["content"], 300)

    forms = [_form_summary(form, base_url) for form in soup.find_all("form")][:10]

    anchors: list[dict[str, str]] = []
    mismatched_links = 0
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        text = compact_whitespace(anchor.get_text(" ", strip=True))[:120]
        absolute = urljoin(base_url, href)
        text_host = None
        if re.match(r"(?i)^https?://", text):
            text_host = (urlsplit(text).hostname or "").lower()
        href_host = (urlsplit(absolute).hostname or "").lower()
        mismatch = bool(text_host and href_host and text_host != href_host)
        if mismatch:
            mismatched_links += 1
        if len(anchors) < 25:
            anchors.append(
                {
                    "text": text,
                    "href": truncate(absolute, 400),
                    "host": href_host,
                    "visible_host_mismatch": str(mismatch).lower(),
                }
            )

    iframes = [
        truncate(urljoin(base_url, iframe.get("src") or ""), 300)
        for iframe in soup.find_all("iframe", src=True)
    ][:10]

    scripts = soup.find_all("script")
    inline_scripts = [script.string or "" for script in scripts if script.string][:10]
    obfuscation = {
        "eval_calls": sum(script.count("eval(") for script in inline_scripts),
        "fromcharcode": sum(script.count("fromCharCode") for script in inline_scripts),
        "atob_calls": sum(script.count("atob(") for script in inline_scripts),
        "unescape_calls": sum(script.count("unescape(") for script in inline_scripts),
        "right_click_disabled": any(
            "contextmenu" in script.lower() and "preventdefault" in script.lower()
            for script in inline_scripts
        ),
        "devtools_check": any(
            "devtools" in script.lower() or "debugger" in script.lower() for script in inline_scripts
        ),
    }

    hidden_texts: list[str] = []
    for element in soup.find_all(style=True):
        style = element.get("style") or ""
        if _HIDDEN_STYLE_RE.search(style):
            text = compact_whitespace(element.get_text(" ", strip=True))
            if text:
                hidden_texts.append(truncate(text, 120))
        if len(hidden_texts) >= 8:
            break

    image_sources = [
        urljoin(base_url, image.get("src"))
        for image in soup.find_all("img", src=True)
        if image.get("src") and not str(image.get("src")).startswith("data:")
    ][:15]
    favicon = soup.find("link", rel=re.compile("icon", re.I))
    favicon_url = urljoin(base_url, favicon.get("href")) if favicon and favicon.get("href") else ""

    visible_text = compact_whitespace(soup.get_text(" ", strip=True))
    password_present = any(form["password_fields"] > 0 for form in forms)
    external_form_targets = [
        form
        for form in forms
        if form["action_host"]
        and registrable_domain(form["action_host"]) != registrable_domain(urlsplit(base_url).hostname or "")
    ]
    iframe_hosts = [urlsplit(url).hostname for url in iframes if url]
    link_urls = [
        item.normalized for item in extract_urls(" ".join(anchor["href"] for anchor in anchors), limit=10)
    ]

    return {
        "title": title,
        "meta_description": meta_description,
        "forms": forms,
        "has_password_form": password_present,
        "external_form_targets": external_form_targets[:5],
        "iframes": iframes,
        "iframe_hosts": iframe_hosts,
        "anchors": anchors,
        "visible_host_mismatches": mismatched_links,
        "obfuscation": obfuscation,
        "hidden_texts": hidden_texts,
        "image_sources": image_sources,
        "favicon_url": truncate(favicon_url, 400),
        "language": (soup.html.get("lang") if soup.html else "") or "",
        "visible_text_excerpt": truncate(visible_text, 3000),
        "link_urls": link_urls,
        "download_links": [
            truncate(urljoin(base_url, anchor["href"]), 300)
            for anchor in anchors
            if re.search(
                r"(?i)\.(apk|exe|msi|zip|rar|7z|scr|js|vbs|bat|cmd|iso|dmg)(?:$|\?)",
                anchor["href"],
            )
        ][:10],
    }


async def fetch_and_inspect(url: str, http: SafeHttpClient) -> dict[str, Any]:
    try:
        fetched = await http.fetch_untrusted(url)
    except NetworkDisabled as exc:
        return {"available": False, "error": str(exc)}
    except UnsafeTarget as exc:
        return {"available": False, "error": f"Blocked by SSRF guard: {exc}"}
    except Exception as exc:  # pragma: no cover - network variability
        return {"available": False, "error": f"{type(exc).__name__}: {truncate(str(exc), 250)}"}

    html = fetched.pop("body", "")
    content_type = fetched.get("content_type") or ""
    parsed: dict[str, Any] = {}
    if "html" in content_type.lower() or html.lstrip().lower().startswith(("<!doctype html", "<html")):
        try:
            parsed = inspect_html(html, fetched.get("final_url") or url)
        except Exception as exc:  # pragma: no cover - malformed HTML
            parsed = {"parse_error": truncate(str(exc), 200)}
    return {
        "available": True,
        "status": fetched.get("status"),
        "content_type": content_type,
        "chain": fetched.get("chain", []),
        "headers": fetched.get("headers", {}),
        "truncated": fetched.get("truncated", False),
        "html": parsed,
        "body_excerpt": "" if parsed else truncate(html, 800),
    }
