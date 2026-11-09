"""Shared domain models used by every module and agent.

These models are deliberately evidence-first: an agent may only raise a finding
that references stored evidence, and the report embeds the complete evidence
ledger plus its integrity state.  That makes every verdict reproducible and
auditable instead of being an unexplainable model score.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field


def utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Verdict(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    MALICIOUS = "malicious"
    INCONCLUSIVE = "inconclusive"


class SignalCategory(StrEnum):
    IDENTITY = "identity"
    PAYMENT = "payment"
    PRESSURE = "pressure"
    LINK = "link"
    THREAT_INTEL = "threat_intel"
    AUTH = "auth"
    VISUAL = "visual"
    CONTENT = "content"
    OBFUSCATION = "obfuscation"
    INFRASTRUCTURE = "infrastructure"


class EvidenceKind(StrEnum):
    MESSAGE_TEXT = "message_text"
    MESSAGE_SIGNAL = "message_signal"
    ENTITY = "entity"
    URL_REFERENCE = "url_reference"
    URL_STATIC = "url_static"
    URL_FETCH = "url_fetch"
    REDIRECT_CHAIN = "redirect_chain"
    DNS = "dns"
    SSL = "ssl"
    RDAP = "rdap"
    THREAT_INTEL = "threat_intel"
    QR_IMAGE = "qr_image"
    QR_PAYLOAD = "qr_payload"
    UPI_URI = "upi_uri"
    IMAGE = "image"
    OCR_TEXT = "ocr_text"
    VLM_OBSERVATION = "vlm_observation"
    IMAGE_SIMILARITY = "image_similarity"
    EMAIL_HEADERS = "email_headers"
    EMAIL_AUTH = "email_auth"
    EMAIL_BODY = "email_body"
    EMAIL_ATTACHMENT = "email_attachment"
    EMAIL_HOP = "email_hop"
    AGENT_ANALYSIS = "agent_analysis"
    VERIFICATION = "verification"


class RecommendationPriority(StrEnum):
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RecommendationCategory(StrEnum):
    CONTAINMENT = "containment"
    VERIFICATION = "verification"
    REPORTING = "reporting"
    PREVENTION = "prevention"
    RECOVERY = "recovery"


class Evidence(BaseModel):
    """A single verifiable observation collected during an investigation."""

    id: str
    kind: EvidenceKind
    source: str = Field(description="Tool or agent that produced the observation")
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    verified: bool = False
    verification_notes: list[str] = Field(default_factory=list)
    collected_at: datetime = Field(default_factory=utcnow)
    sha256: str = ""
    prev_hash: str = ""
    chain_hash: str = ""

    def digest_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "source": self.source,
            "summary": self.summary,
            "data": self.data,
            "confidence": self.confidence,
            "collected_at": self.collected_at.isoformat(),
        }


class Signal(BaseModel):
    """A weighted, explainable indicator. Signals are *never* opaque scores."""

    id: str
    category: SignalCategory
    label: str
    description: str
    weight: int = Field(ge=0, le=45)
    severity: Severity = Severity.MEDIUM
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    source: str = "engine"


class Finding(BaseModel):
    id: str
    agent: str
    title: str
    description: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class RiskFactor(BaseModel):
    id: str
    label: str
    category: SignalCategory
    weight: int
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    severity: Severity
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    factors: list[RiskFactor] = Field(default_factory=list)
    category_scores: dict[str, int] = Field(default_factory=dict)
    summary: str = ""
    confidence_basis: str = ""
    evidence_coverage: float = Field(default=0.0, ge=0.0, le=1.0)


class Recommendation(BaseModel):
    title: str
    detail: str
    priority: RecommendationPriority = RecommendationPriority.MEDIUM
    category: RecommendationCategory = RecommendationCategory.PREVENTION


class IOC(BaseModel):
    type: Literal[
        "url",
        "domain",
        "ip",
        "email",
        "phone",
        "upi_id",
        "bank_account",
        "crypto_wallet",
        "file_hash",
        "filename",
        "brand",
    ]
    value: str
    risk: Severity = Severity.MEDIUM
    context: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


class AgentTraceEntry(BaseModel):
    agent: str
    step: str
    action: str
    tool: str | None = None
    detail: str = ""
    status: Literal["ok", "warning", "error", "skipped"] = "ok"
    latency_ms: int = 0
    model: str | None = None


class ModelInfo(BaseModel):
    text_model: str
    vision_model: str
    reasoning_mode: Literal["huggingface", "offline-expert-system"] = "offline-expert-system"
    degraded: bool = True
    providers: list[str] = Field(default_factory=list)
    notes: str = ""


class URLSignal(BaseModel):
    id: str
    label: str
    detail: str
    severity: Severity = Severity.MEDIUM
    weight: int = Field(default=8, ge=0, le=45)
    category: SignalCategory = SignalCategory.LINK
    evidence_ids: list[str] = Field(default_factory=list)


class SSLInfo(BaseModel):
    valid: bool = False
    # ``False`` when no TLS endpoint could be reached (DNS failure, timeout,
    # connection refused).  In that case nothing at all can be concluded about
    # the certificate, so ``valid=False`` must NOT be treated as evidence of a
    # bad certificate.
    inspected: bool = True
    issuer: str | None = None
    subject: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    san: list[str] = Field(default_factory=list)
    tls_version: str | None = None
    error: str | None = None


class DNSInfo(BaseModel):
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)
    spf: str | None = None
    dmarc: str | None = None
    dmarc_policy: str | None = None
    errors: list[str] = Field(default_factory=list)


class ThreatIntelSourceResult(BaseModel):
    source: str
    status: Literal["clean", "suspicious", "malicious", "unknown", "error", "not_configured"]
    detail: str = ""
    score: int | None = None
    positives: int | None = None
    total: int | None = None
    raw_summary: dict[str, Any] = Field(default_factory=dict)


class URLIntelligence(BaseModel):
    url: str
    normalized_url: str
    final_url: str | None = None
    scheme: str = "https"
    host: str = ""
    domain: str = ""
    suffix: str = ""
    registered_domain: str = ""
    is_ip_literal: bool = False
    is_punycode: bool = False
    decoded_host: str | None = None
    is_shortener: bool = False
    redirects: list[str] = Field(default_factory=list)
    dns: DNSInfo | None = None
    ssl: SSLInfo | None = None
    domain_age_days: int | None = None
    threat_intel: list[ThreatIntelSourceResult] = Field(default_factory=list)
    page: dict[str, Any] = Field(default_factory=dict)
    signals: list[URLSignal] = Field(default_factory=list)
    reputation_score: int = Field(default=0, ge=0, le=100)
    verdict: Verdict = Verdict.INCONCLUSIVE
    evidence_ids: list[str] = Field(default_factory=list)


class UPIInfo(BaseModel):
    raw: str
    scheme: str = "upi"
    payee_vpa: str | None = None
    payee_name: str | None = None
    amount: str | None = None
    currency: str | None = None
    transaction_note: str | None = None
    merchant_code: str | None = None
    transaction_ref: str | None = None
    handle: str | None = None
    is_known_handle: bool = False
    warnings: list[str] = Field(default_factory=list)


class ReportSummary(BaseModel):
    """Compact, safe representation returned by list endpoints."""

    id: str
    module: str
    created_at: datetime
    verdict: Verdict
    severity: Severity
    risk_score: int
    input_summary: str


class InvestigationReport(BaseModel):
    id: str
    module: Literal["message", "qr", "visual", "email"]
    created_at: datetime = Field(default_factory=utcnow)
    completed_at: datetime | None = None
    language: str = "en"
    input_summary: str = ""
    verdict: Verdict = Verdict.INCONCLUSIVE
    severity: Severity = Severity.INFO
    risk_score: int = 0
    confidence: float = 0.0
    executive_summary: str = ""
    technical_summary: str = ""
    risk: RiskAssessment | None = None
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    entities: dict[str, Any] = Field(default_factory=dict)
    agent_trace: list[AgentTraceEntry] = Field(default_factory=list)
    plan: dict[str, Any] = Field(default_factory=dict)
    model: ModelInfo | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_chain_valid: bool = False
    degraded: bool = True
    markdown: str = ""
    report_version: str = "1.0"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def evidence_count(self) -> int:
        return len(self.evidence)


class ReportEnvelope(BaseModel):
    investigation_id: str
    module: Literal["message", "qr", "visual", "email"]
    report: InvestigationReport


class InvestigationStartResponse(BaseModel):
    investigation_id: str
    status: Literal["completed", "failed"] = "completed"
    report_url: str
