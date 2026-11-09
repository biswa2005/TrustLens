from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field
from links.models_tls import TLSReport

Severity = Literal["info", "weak", "moderate", "strong"]
CheckStatus = Literal["ok", "unavailable", "skipped", "error"]
RiskClass = Literal["low", "suspicious", "high", "confirmed_malicious", "inconclusive"]
TargetKind = Literal["input", "hop", "final_destination"]

class NormalisedURL(BaseModel):
    original: str
    normalised: str
    scheme: str
    host: str
    host_unicode: str
    registered_domain: str
    subdomain: str
    suffix: str
    port: int | None = None
    path: str
    query: str
    embedded_urls: list[str] = Field(default_factory=list)
    is_idn: bool = False
    is_ip_host: bool = False
    canonical_host: str | None = None
    ip_value: str | None = None
    obfuscation_flags: list[str] = Field(default_factory=list)
    parser_disagreement: bool = False

class Finding(BaseModel):
    id: str
    check_id: str
    category: str
    title: str
    severity: Severity
    evidence: dict[str, Any] = Field(default_factory=dict)
    source: str = "local-rules"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    limitation: str | None = None
    dampenable: bool = False
    evidence_group: str = ""
    evidence_class: Literal["static", "behavioural", "infrastructure", "reputation"] = "static"
    target: TargetKind = "input"

class CheckResult(BaseModel):
    check_id: str
    status: CheckStatus
    reason: str | None = None
    duration_ms: int = 0

class Hop(BaseModel):
    url: str
    status: int | None = None
    location: str | None = None
    resolved_ip: str | None = None
    registered_domain: str | None = None
    scheme: str
    content_type: str | None = None
    elapsed_ms: int = 0
    via: Literal["start", "http3xx", "meta_refresh", "refresh_header", "js_literal"] = "start"
    blocked_reason: str | None = None
    relation: Literal["start", "same_site", "cross_site", "known_pair"] = "start"
    notes: list[str] = Field(default_factory=list)

class Coverage(BaseModel):
    completed: int
    planned: int = 11
    checks: list[CheckResult]

class Target(BaseModel):
    url: str
    host: str
    registered_domain: str
    target: TargetKind

class IntelMatch(BaseModel):
    source: str
    match_level: Literal["exact_url", "host", "registered_domain"]
    threat_type: str | None = None
    report_link: str | None = None
    first_seen: datetime | None = None
    queried_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_summary: dict[str, Any] = Field(default_factory=dict)

class DomainInfo(BaseModel):
    registrar: str | None = None
    created: datetime | None = None
    age_days: int | None = None
    nameservers: list[str] = Field(default_factory=list)
    a_records: list[str] = Field(default_factory=list)
    aaaa_records: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    ttl: int | None = None

class EvidenceGroup(BaseModel):
    group: str
    evidence_class: Literal["static", "behavioural", "infrastructure", "reputation"]
    severity: Severity
    rules: list[str] = Field(default_factory=list)
    targets: list[TargetKind] = Field(default_factory=list)

class RedirectSummary(BaseModel):
    start_registered_domain: str
    final_registered_domain: str | None = None
    hop_count: int = 0
    chain_complete: bool = False
    cross_site: bool = False
    via_shortener: bool = False
    blocked: bool = False
    target_domains_analysed: list[str] = Field(default_factory=list)

class Report(BaseModel):
    report_id: str | None = None
    input: str
    normalised_url: NormalisedURL | None = None
    risk_class: RiskClass = "inconclusive"
    risk_reasoning: list[str] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "low"
    evidence_groups: list[EvidenceGroup] = Field(default_factory=list)
    redirect_summary: RedirectSummary | None = None
    coverage: Coverage
    findings: list[Finding] = Field(default_factory=list)
    redirect_chain: list[Hop] = Field(default_factory=list)
    intel_matches: list[IntelMatch] = Field(default_factory=list)
    domain_info: DomainInfo | None = None
    recommendations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    tls_reports: dict[str, TLSReport] | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
