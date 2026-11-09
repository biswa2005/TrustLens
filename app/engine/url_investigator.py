"""End-to-end URL/domain investigation used by the URL Intelligence agent."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.config import Settings
from app.engine.brands import get_brand_registry
from app.engine.dns_ssl import DNSAnalyzer, RDAPAnalyzer, TLSAnalyzer
from app.engine.net import SafeHttpClient
from app.engine.threat_intel import ThreatIntelCorrelator
from app.engine.urls import StaticURLResult, analyze_url_static, normalize_url, registrable_domain
from app.engine.utils import dedupe, signal_id, truncate
from app.engine.web import fetch_and_inspect
from app.schemas import (
    Severity,
    SignalCategory,
    URLIntelligence,
    URLSignal,
    Verdict,
)

logger = logging.getLogger(__name__)


class URLInvestigator:
    def __init__(
        self,
        settings: Settings,
        http: SafeHttpClient,
        dns: DNSAnalyzer,
        tls: TLSAnalyzer,
        rdap: RDAPAnalyzer,
        intel: ThreatIntelCorrelator,
    ) -> None:
        self.settings = settings
        self.http = http
        self.dns = dns
        self.tls = tls
        self.rdap = rdap
        self.intel = intel
        self.brands = get_brand_registry()

    async def investigate(
        self,
        url: str,
        *,
        fetch_page: bool | None = None,
        max_urls: int | None = None,
    ) -> dict[str, Any]:
        normalized = normalize_url(url)
        static = analyze_url_static(normalized, brands=self.brands)
        host = static.host
        registered = static.registered_domain or registrable_domain(host)
        should_fetch = (
            self.settings.enable_page_fetch if fetch_page is None else fetch_page
        ) and not static.is_ip_literal

        dns_info = None
        ssl_info = None
        rdap_info: dict[str, Any] = {"available": False}
        page_info: dict[str, Any] = {"available": False}
        final_url = normalized
        final_static: StaticURLResult | None = None

        # DNS is inspected for the registered domain (records, SPF, DMARC) *and*
        # for the exact host: a lookalike or expired subdomain often fails to
        # resolve even when its parent domain is healthy and long-registered.
        host_needs_dns = bool(host) and not static.is_ip_literal and bool(registered) and host != registered

        gather_targets: list[Any] = []
        if registered:
            gather_targets.append(self.dns.lookup(registered))
        else:
            gather_targets.append(_none())
        if host_needs_dns:
            gather_targets.append(self.dns.lookup(host))
        else:
            gather_targets.append(_none())
        if host and (static.scheme == "https" or should_fetch):
            gather_targets.append(self.tls.inspect(host, static.port or 443))
        else:
            gather_targets.append(_none())
        if registered:
            gather_targets.append(self.rdap.lookup(registered))
        else:
            gather_targets.append(_none())
        if should_fetch:
            gather_targets.append(fetch_and_inspect(normalized, self.http))
        else:
            gather_targets.append(_none())

        dns_info, host_dns, ssl_info, rdap_info, page_info = await asyncio.gather(*gather_targets)
        rdap_info = rdap_info or {"available": False}
        page_info = page_info or {"available": False}

        if page_info.get("available") and page_info.get("chain"):
            final_url = page_info["chain"][-1].get("url") or normalized
            if normalize_url(final_url) != normalized:
                final_static = analyze_url_static(final_url, brands=self.brands)

        ips = list(dns_info.a) if dns_info else []
        intel_results = await self.intel.check_url(normalized, registered or host, ips)

        signals: list[URLSignal] = []
        notes: list[str] = []

        def add(
            identifier: str,
            label: str,
            detail: str,
            weight: int,
            severity: Severity,
            category: SignalCategory = SignalCategory.LINK,
        ) -> None:
            signals.append(
                URLSignal(
                    id=signal_id("url", identifier, detail[:80]),
                    label=label,
                    detail=detail,
                    weight=weight,
                    severity=severity,
                    category=category,
                )
            )

        signals.extend(static.signals)
        if final_static:
            signals.extend(final_static.signals)
            add(
                "redirect_destination",
                "Redirects to a different site",
                f"The link redirects to '{truncate(final_url, 240)}'.",
                6,
                Severity.MEDIUM,
            )

        malicious_sources = [
            item for item in intel_results if item.status == "malicious"
        ]
        suspicious_sources = [
            item for item in intel_results if item.status == "suspicious"
        ]
        for result in malicious_sources:
            add(
                f"ti_malicious_{result.source}",
                f"Threat intelligence match: {result.source}",
                result.detail,
                40,
                Severity.CRITICAL,
                SignalCategory.THREAT_INTEL,
            )
        for result in suspicious_sources:
            add(
                f"ti_suspicious_{result.source}",
                f"Suspicious reputation: {result.source}",
                result.detail,
                22,
                Severity.HIGH,
                SignalCategory.THREAT_INTEL,
            )
        clean_sources = [item.source for item in intel_results if item.status == "clean"]
        if clean_sources:
            notes.append("No listing at: " + ", ".join(clean_sources) + " (not proof of safety).")

        if dns_info and not (dns_info.a or dns_info.aaaa or dns_info.cname):
            add(
                "no_dns_records",
                "Domain does not resolve",
                "No A/AAAA/CNAME records were returned; the domain may be inactive, parked or newly created.",
                8,
                Severity.MEDIUM,
                SignalCategory.INFRASTRUCTURE,
            )
        if dns_info and dns_info.errors:
            notes.extend(dns_info.errors)

        host_resolves = True
        if host_dns is not None:
            host_resolves = bool(host_dns.a or host_dns.aaaa or host_dns.cname)
            notes.extend(host_dns.errors or [])
        if not host_resolves:
            add(
                "host_does_not_resolve",
                "Host does not resolve",
                f"'{host}' returned no A/AAAA/CNAME records, although the parent domain "
                f"'{registered}' does. The link may be expired, parked, typo-squatted or "
                "deliberately short-lived; it cannot be opened as written.",
                10,
                Severity.MEDIUM,
                SignalCategory.INFRASTRUCTURE,
            )

        if ssl_info:
            if not ssl_info.valid:
                if ssl_info.inspected:
                    add(
                        "invalid_tls",
                        "Invalid or untrusted TLS certificate",
                        ssl_info.error or "The certificate chain or hostname did not validate.",
                        16,
                        Severity.HIGH,
                        SignalCategory.INFRASTRUCTURE,
                    )
                else:
                    # No endpoint was reached (DNS/timeout/connection), so the
                    # certificate was never presented.  Recording this as an
                    # "invalid certificate" would invent evidence we do not have.
                    notes.append(
                        "TLS not inspected: " + truncate(ssl_info.error or "no endpoint reached", 200)
                    )
            elif ssl_info.days_remaining is not None and ssl_info.days_remaining < 0:
                add(
                    "expired_tls",
                    "Expired TLS certificate",
                    f"The certificate expired {abs(ssl_info.days_remaining)} days ago.",
                    14,
                    Severity.HIGH,
                    SignalCategory.INFRASTRUCTURE,
                )
            else:
                notes.append(
                    "TLS certificate is valid"
                    + (f", issued by {ssl_info.issuer}" if ssl_info.issuer else "")
                    + (f", {ssl_info.days_remaining} days remaining" if ssl_info.days_remaining is not None else "")
                    + "."
                )

        age_days = rdap_info.get("age_days") if isinstance(rdap_info, dict) else None
        if isinstance(age_days, int):
            if age_days < 30:
                add(
                    "very_new_domain",
                    "Very recently registered domain",
                    f"RDAP shows the domain was registered {age_days} days ago — common for disposable phishing sites.",
                    16,
                    Severity.HIGH,
                    SignalCategory.INFRASTRUCTURE,
                )
            elif age_days < 90:
                add(
                    "new_domain",
                    "Recently registered domain",
                    f"RDAP shows the domain was registered {age_days} days ago.",
                    8,
                    Severity.MEDIUM,
                    SignalCategory.INFRASTRUCTURE,
                )
            else:
                notes.append(f"Domain age: {age_days} days (RDAP).")

        if page_info.get("available"):
            html = page_info.get("html") or {}
            if html.get("has_password_form") and not self.brands.is_official(host):
                add(
                    "password_form_unofficial",
                    "Password form on a non-official domain",
                    "The page asks for a password but the host is not an official brand domain.",
                    20,
                    Severity.HIGH,
                    SignalCategory.VISUAL,
                )
            if html.get("external_form_targets"):
                targets = ", ".join(
                    item.get("action_host", "") for item in html["external_form_targets"][:3]
                )
                add(
                    "external_form_target",
                    "Login form posts to another domain",
                    f"Credential form posts to: {targets}.",
                    20,
                    Severity.HIGH,
                    SignalCategory.VISUAL,
                )
            if int(html.get("visible_host_mismatches") or 0) > 0:
                add(
                    "link_text_mismatch",
                    "Displayed links hide their real destination",
                    f"{html['visible_host_mismatches']} link(s) show a different host in their text.",
                    12,
                    Severity.HIGH,
                    SignalCategory.CONTENT,
                )
            if html.get("hidden_texts"):
                add(
                    "hidden_page_text",
                    "Hidden text on page",
                    "The page contains hidden text blocks, often used to manipulate filters or readers.",
                    7,
                    Severity.MEDIUM,
                    SignalCategory.OBFUSCATION,
                )
            obfuscation = html.get("obfuscation") or {}
            if obfuscation.get("eval_calls") or obfuscation.get("fromcharcode") or obfuscation.get("atob_calls"):
                add(
                    "script_obfuscation",
                    "Obfuscated JavaScript",
                    "Inline scripts use eval/atob/fromCharCode constructs that can hide behaviour.",
                    9,
                    Severity.MEDIUM,
                    SignalCategory.OBFUSCATION,
                )
            if html.get("download_links"):
                add(
                    "page_download_links",
                    "Page offers direct downloads",
                    "Download links: " + ", ".join(html["download_links"][:3]),
                    12,
                    Severity.HIGH,
                    SignalCategory.CONTENT,
                )
            if html.get("title"):
                notes.append(f"Page title: {html['title']}")
        elif page_info.get("error"):
            notes.append(f"Page fetch: {page_info['error']}")

        reputation = min(100, sum(signal.weight for signal in signals))
        if any(item.status == "malicious" for item in intel_results) or reputation >= 70:
            verdict = Verdict.MALICIOUS
        elif reputation >= 45 or any(item.status == "suspicious" for item in intel_results):
            verdict = Verdict.LIKELY_MALICIOUS if reputation >= 45 else Verdict.SUSPICIOUS
        elif reputation >= 20:
            verdict = Verdict.SUSPICIOUS
        elif not any(item.status in {"clean", "malicious", "suspicious"} for item in intel_results):
            verdict = Verdict.INCONCLUSIVE
        else:
            verdict = Verdict.BENIGN

        # Deduplicate URL signals by id
        unique_signals = {signal.id: signal for signal in signals}
        intel_model = URLIntelligence(
            url=url,
            normalized_url=normalized,
            final_url=final_url,
            scheme=static.scheme,
            host=host,
            domain=static.domain,
            suffix=static.suffix,
            registered_domain=registered,
            is_ip_literal=static.is_ip_literal,
            is_punycode=static.is_punycode,
            decoded_host=static.decoded_host,
            is_shortener=static.is_shortener,
            redirects=[item.get("url", "") for item in (page_info.get("chain") or [])],
            dns=dns_info,
            ssl=ssl_info,
            domain_age_days=age_days if isinstance(age_days, int) else None,
            threat_intel=intel_results,
            page={
                "available": page_info.get("available", False),
                "status": page_info.get("status"),
                "title": (page_info.get("html") or {}).get("title"),
                "has_password_form": (page_info.get("html") or {}).get("has_password_form"),
                "external_form_targets": (page_info.get("html") or {}).get("external_form_targets"),
                "error": page_info.get("error"),
            },
            signals=sorted(unique_signals.values(), key=lambda item: item.weight, reverse=True),
            reputation_score=reputation,
            verdict=verdict,
        )
        summary_parts = [
            f"{normalized} → host {host}",
            f"reputation score {reputation}/100",
            f"verdict {verdict.value}",
        ]
        if static.brand_match:
            summary_parts.append(f"brand reference {static.brand_match}")
        if intel_results:
            summary_parts.append(
                "threat intel: "
                + ", ".join(f"{item.source}={item.status}" for item in intel_results[:6])
            )
        if notes:
            summary_parts.append("notes: " + " ".join(notes[:4]))
        return {
            "url": url,
            "normalized_url": normalized,
            "final_url": final_url,
            "static": static.to_dict(),
            "dns": dns_info.model_dump(mode="json") if dns_info else None,
            "ssl": ssl_info.model_dump(mode="json") if ssl_info else None,
            "rdap": rdap_info,
            "threat_intel": [item.model_dump(mode="json") for item in intel_results],
            "page": page_info,
            "signals": intel_model.signals,
            "reputation_score": reputation,
            "verdict": verdict,
            "summary": "; ".join(summary_parts),
            "notes": dedupe(notes),
            "model": intel_model,
            "iocs": {
                "domains": dedupe([registered, final_static.registered_domain if final_static else ""]),
                "urls": dedupe([normalized, final_url]),
                "ips": ips,
            },
        }


async def _none() -> None:
    return None
