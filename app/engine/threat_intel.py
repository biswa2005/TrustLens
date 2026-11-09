"""Threat-intelligence correlation across public APIs.

All providers are optional.  A missing key is reported as ``not_configured``
rather than silently treated as "clean" — absence of evidence is not evidence
of absence.
"""

from __future__ import annotations

import base64
import logging

import httpx

from app.config import Settings
from app.engine.cache import TTLCache
from app.engine.net import NetworkDisabled, SafeHttpClient
from app.engine.utils import truncate
from app.schemas import ThreatIntelSourceResult

logger = logging.getLogger(__name__)


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class ThreatIntelCorrelator:
    def __init__(self, settings: Settings, http: SafeHttpClient, cache: TTLCache | None = None) -> None:
        self.settings = settings
        self.http = http
        self.cache = cache or TTLCache(default_ttl=settings.threat_intel_cache_ttl)

    async def check_url(self, url: str, domain: str, ips: list[str] | None = None) -> list[ThreatIntelSourceResult]:
        cache_key = f"ti:{url}"
        cached = self.cache.get(cache_key)
        if isinstance(cached, list):
            return cached
        if not self.settings.allow_network:
            return [
                ThreatIntelSourceResult(
                    source="threat-intelligence",
                    status="not_configured",
                    detail="Network access disabled; no reputation lookups were made.",
                )
            ]

        results: list[ThreatIntelSourceResult] = []
        providers = [
            self._google_safe_browsing(url),
            self._virustotal(url),
            self._urlhaus(url),
            self._urlscan(domain),
        ]
        if ips:
            providers.append(self._abuseipdb(ips[0]))
        for provider in providers:
            try:
                results.append(await provider)
            except NetworkDisabled:
                results.append(
                    ThreatIntelSourceResult(source="network", status="not_configured", detail="disabled")
                )
            except Exception as exc:  # pragma: no cover - provider variability
                logger.info("Threat intel provider failed: %s", exc)
                results.append(
                    ThreatIntelSourceResult(
                        source=getattr(provider, "__name__", "provider"),
                        status="error",
                        detail=truncate(f"{type(exc).__name__}: {exc}", 250),
                    )
                )
        if not results:
            results.append(
                ThreatIntelSourceResult(
                    source="threat-intelligence",
                    status="not_configured",
                    detail="No threat-intelligence providers are configured.",
                )
            )
        self.cache.set(cache_key, results, ttl=self.settings.threat_intel_cache_ttl)
        return results

    # ------------------------------------------------------------- providers
    async def _google_safe_browsing(self, url: str) -> ThreatIntelSourceResult:
        key = self.settings.google_safe_browsing_api_key
        if not key:
            return ThreatIntelSourceResult(
                source="google-safe-browsing", status="not_configured", detail="GOOGLE_SAFE_BROWSING_API_KEY not set"
            )
        endpoint = (
            "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={key.get_secret_value()}"
        )
        payload = {
            "client": {"clientId": "threatlens", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        status, data = await self.http.api_post_json(endpoint, json=payload)
        if status >= 400:
            return ThreatIntelSourceResult(
                source="google-safe-browsing", status="error", detail=f"HTTP {status}"
            )
        matches = data.get("matches") or []
        if matches:
            types = sorted({match.get("threatType", "UNKNOWN") for match in matches})
            return ThreatIntelSourceResult(
                source="google-safe-browsing",
                status="malicious",
                detail="Listed by Google Safe Browsing: " + ", ".join(types),
                raw_summary={"threat_types": types},
            )
        return ThreatIntelSourceResult(
            source="google-safe-browsing", status="clean", detail="No Safe Browsing match."
        )

    async def _virustotal(self, url: str) -> ThreatIntelSourceResult:
        key = self.settings.virustotal_api_key
        if not key:
            return ThreatIntelSourceResult(
                source="virustotal", status="not_configured", detail="VIRUSTOTAL_API_KEY not set"
            )
        endpoint = f"https://www.virustotal.com/api/v3/urls/{_vt_url_id(url)}"
        status, data = await self.http.api_get_json(
            endpoint, headers={"x-apikey": key.get_secret_value()}
        )
        if status == 404:
            return ThreatIntelSourceResult(
                source="virustotal", status="unknown", detail="URL has not been submitted to VirusTotal."
            )
        if status >= 400:
            return ThreatIntelSourceResult(source="virustotal", status="error", detail=f"HTTP {status}")
        attributes = (data.get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        total = malicious + suspicious + harmless + int(stats.get("undetected", 0) or 0)
        if malicious >= 2:
            state = "malicious"
        elif malicious == 1 or suspicious >= 2:
            state = "suspicious"
        elif total:
            state = "clean"
        else:
            state = "unknown"
        return ThreatIntelSourceResult(
            source="virustotal",
            status=state,
            detail=f"{malicious} malicious / {suspicious} suspicious of {total} engines.",
            positives=malicious + suspicious,
            total=total,
            raw_summary={"stats": stats, "categories": attributes.get("categories", {})},
        )

    async def _urlhaus(self, url: str) -> ThreatIntelSourceResult:
        status, data = await self.http.api_post_json(
            "https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}
        )
        if status >= 400:
            return ThreatIntelSourceResult(source="urlhaus", status="error", detail=f"HTTP {status}")
        query_status = data.get("query_status")
        if query_status == "no_results":
            return ThreatIntelSourceResult(source="urlhaus", status="clean", detail="Not present in URLhaus.")
        if query_status == "ok":
            state = "malicious" if (data.get("url_status") or "").lower() == "online" else "suspicious"
            return ThreatIntelSourceResult(
                source="urlhaus",
                status=state,
                detail=(
                    f"URLhaus: {data.get('threat', 'malware URL')} "
                    f"(status={data.get('url_status')}, tags={','.join(data.get('tags') or [])})"
                ),
                raw_summary={
                    "threat": data.get("threat"),
                    "tags": data.get("tags", []),
                    "date_added": data.get("date_added"),
                },
            )
        return ThreatIntelSourceResult(
            source="urlhaus",
            status="unknown",
            detail=truncate(str(data.get("query_status") or "unexpected response"), 200),
        )

    async def _urlscan(self, domain: str) -> ThreatIntelSourceResult:
        key = self.settings.urlscan_api_key
        if not key:
            return ThreatIntelSourceResult(
                source="urlscan", status="not_configured", detail="URLSCAN_API_KEY not set"
            )
        if not domain:
            return ThreatIntelSourceResult(source="urlscan", status="unknown", detail="No domain")
        status, data = await self.http.api_get_json(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 20},
            headers={"api-key": key.get_secret_value()},
        )
        if status >= 400:
            return ThreatIntelSourceResult(source="urlscan", status="error", detail=f"HTTP {status}")
        results = data.get("results") or []
        malicious = 0
        for result in results:
            verdicts = ((result.get("verdicts") or {}).get("overall") or {})
            if verdicts.get("malicious") or verdicts.get("score", 0) >= 50:
                malicious += 1
        if malicious:
            return ThreatIntelSourceResult(
                source="urlscan",
                status="malicious" if malicious >= 2 else "suspicious",
                detail=f"{malicious} of {len(results)} recent URLscan results are flagged malicious.",
                positives=malicious,
                total=len(results),
            )
        return ThreatIntelSourceResult(
            source="urlscan",
            status="clean" if results else "unknown",
            detail=f"{len(results)} recent scans, none flagged malicious.",
            total=len(results),
        )

    async def _abuseipdb(self, ip: str) -> ThreatIntelSourceResult:
        key = self.settings.abuseipdb_api_key
        if not key:
            return ThreatIntelSourceResult(
                source="abuseipdb", status="not_configured", detail="ABUSEIPDB_API_KEY not set"
            )
        status, data = await self.http.api_get_json(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key.get_secret_value(), "Accept": "application/json"},
        )
        if status >= 400:
            return ThreatIntelSourceResult(source="abuseipdb", status="error", detail=f"HTTP {status}")
        score = int((data.get("data") or {}).get("abuseConfidenceScore", 0) or 0)
        state = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
        return ThreatIntelSourceResult(
            source="abuseipdb",
            status=state,
            detail=f"Abuse confidence {score}/100 for {ip}.",
            score=score,
        )

    async def _phishtank(self, url: str) -> ThreatIntelSourceResult:
        key = self.settings.phishtank_api_key
        if not key:
            return ThreatIntelSourceResult(
                source="phishtank", status="not_configured", detail="PHISHTANK_API_KEY not set"
            )
        try:
            response = await self.http.api_post_json(
                "https://checkurl.phishtank.com/checkurl/",
                data={
                    "url": url,
                    "format": "json",
                    "app_key": key.get_secret_value(),
                },
                headers={"User-Agent": self.settings.user_agent},
            )
            status, data = response
        except httpx.HTTPError as exc:
            return ThreatIntelSourceResult(
                source="phishtank", status="error", detail=truncate(str(exc), 200)
            )
        if status >= 400:
            return ThreatIntelSourceResult(source="phishtank", status="error", detail=f"HTTP {status}")
        results = data.get("results") or {}
        if results.get("in_database"):
            if results.get("valid"):
                return ThreatIntelSourceResult(
                    source="phishtank", status="malicious", detail="URL is a verified PhishTank phish."
                )
            return ThreatIntelSourceResult(
                source="phishtank", status="suspicious", detail="URL exists in PhishTank but is not verified."
            )
        return ThreatIntelSourceResult(source="phishtank", status="clean", detail="Not in PhishTank.")
