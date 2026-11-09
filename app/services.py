"""Composition root for the shared investigation engine."""

from __future__ import annotations

import logging

from app.config import Settings, get_settings
from app.engine.brands import get_brand_registry
from app.engine.cache import TTLCache
from app.engine.dns_ssl import DNSAnalyzer, RDAPAnalyzer, TLSAnalyzer
from app.engine.llm import LLMService
from app.engine.net import SafeHttpClient
from app.engine.report import ReportStore
from app.engine.threat_intel import ThreatIntelCorrelator
from app.engine.url_investigator import URLInvestigator

logger = logging.getLogger(__name__)


class ForensicServices:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.llm = LLMService(self.settings)
        self.cache = TTLCache(max_size=4096, default_ttl=3600)
        self.http = SafeHttpClient(self.settings)
        self.dns = DNSAnalyzer(self.settings, self.cache)
        self.tls = TLSAnalyzer(self.settings, self.cache)
        self.rdap = RDAPAnalyzer(self.settings, self.http, self.cache)
        self.intel = ThreatIntelCorrelator(self.settings, self.http, self.cache)
        self.brands = get_brand_registry()
        self.urls = URLInvestigator(
            self.settings, self.http, self.dns, self.tls, self.rdap, self.intel
        )
        self.reports = ReportStore(self.settings)

    async def close(self) -> None:
        await self.llm.close()
        await self.http.close()


def build_services(settings: Settings | None = None) -> ForensicServices:
    return ForensicServices(settings)
