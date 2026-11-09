"""The tool layer shared by all agents.

Tools perform deterministic forensic work and write tamper-evident evidence to
the investigation ledger.  Agents decide which optional tools to call; the
mandatory pipeline guarantees that core evidence is collected even if the
language model is unavailable.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlsplit

from app.agents.types import ToolResult, ToolSpec
from app.config import Settings
from app.engine.brands import BrandRegistry, get_brand_registry
from app.engine.email_auth import verify_email_auth as verify_email_auth_engine
from app.engine.email_utils import FREE_MAIL_DOMAINS
from app.engine.email_utils import parse_email as parse_email_engine
from app.engine.evidence import EvidenceStore
from app.engine.image_utils import (
    basic_image_evidence,
    compare_with_reference,
    prepare_for_vlm,
    try_local_ocr,
)
from app.engine.llm import LLMService
from app.engine.qr_utils import decode_qr_image, inspect_payload
from app.engine.text_signals import analyze_message_text
from app.engine.urls import extract_urls, normalize_url, registrable_domain
from app.engine.urls import parse_upi_uri as parse_upi
from app.engine.utils import dedupe, sha256_text, signal_id, truncate
from app.schemas import (
    IOC,
    Evidence,
    EvidenceKind,
    Severity,
    Signal,
    SignalCategory,
    URLSignal,
    Verdict,
)
from app.services import ForensicServices

logger = logging.getLogger(__name__)


def _tls_evidence_meta(info: dict[str, Any]) -> tuple[str, float, bool]:
    """Return (status label, confidence, verified) for a TLS inspection result.

    ``inspected=False`` means we never reached a TLS endpoint (DNS failure,
    timeout, refused connection), so the certificate was never presented.  Such
    an observation must be labelled *not inspected* with low confidence and
    ``verified=False`` instead of being recorded as a verified bad certificate.
    """
    if info.get("valid"):
        return "valid", 0.92, True
    if info.get("inspected", True):
        return "invalid", 0.92, True
    return "not inspected (host unreachable)", 0.4, False


class Toolbox:
    def __init__(
        self,
        settings: Settings,
        llm: LLMService,
        services: ForensicServices,
        store: EvidenceStore,
        artifacts: dict[str, Any],
    ) -> None:
        self.settings = settings
        self.llm = llm
        self.services = services
        self.store = store
        self.artifacts = artifacts
        self.brands: BrandRegistry = get_brand_registry()

    # ------------------------------------------------------------- evidence
    def _add(
        self,
        kind: EvidenceKind,
        summary: str,
        data: dict[str, Any],
        *,
        confidence: float = 0.85,
        verified: bool = False,
        notes: list[str] | None = None,
    ) -> Evidence:
        return self.store.add(
            kind,
            source="toolbox",
            summary=summary,
            data=data,
            confidence=confidence,
            verified=verified,
            verification_notes=notes,
        )

    def _signal(
        self,
        identifier: str,
        label: str,
        detail: str,
        weight: int,
        severity: Severity,
        category: SignalCategory,
        evidence_ids: list[str],
        *,
        confidence: float = 0.86,
        source: str = "toolbox",
    ) -> Signal:
        return Signal(
            id=signal_id(identifier, detail[:120]),
            category=category,
            label=label,
            description=detail,
            weight=weight,
            severity=severity,
            evidence_ids=evidence_ids,
            confidence=confidence,
            source=source,
        )

    @staticmethod
    def _url_signals(signals: list[URLSignal], evidence_id: str, source: str) -> list[Signal]:
        return [
            Signal(
                id=signal.id,
                category=signal.category,
                label=signal.label,
                description=signal.detail,
                weight=signal.weight,
                severity=signal.severity,
                evidence_ids=[evidence_id],
                confidence=0.9,
                source=source,
            )
            for signal in signals
        ]

    # ---------------------------------------------------------------- specs
    def specs(self, names: list[str]) -> list[ToolSpec]:
        registry: dict[str, ToolSpec] = {
            "analyze_message": ToolSpec(
                name="analyze_message",
                description=(
                    "Run multilingual scam/manipulation analysis over message text. Returns language, "
                    "scam-type hypotheses, quoted manipulation tactics and extracted entities."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Message body to analyse"},
                        "language": {
                            "type": "string",
                            "enum": ["auto", "en", "hi", "bn", "hinglish"],
                            "default": "auto",
                        },
                        "channel": {"type": "string", "default": "sms"},
                        "sender": {"type": "string"},
                    },
                    "required": ["text"],
                },
                handler=self.analyze_message,
            ),
            "extract_urls": ToolSpec(
                name="extract_urls",
                description="Extract and normalise URLs (including defanged links) from text.",
                parameters={
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
                handler=self.extract_urls_tool,
            ),
            "decode_qr": ToolSpec(
                name="decode_qr",
                description=(
                    "Decode the uploaded QR image with OpenCV (multiple preprocessing passes) and "
                    "interpret URL/UPI/WiFi/vCard/crypto payloads."
                ),
                parameters={"type": "object", "properties": {}},
                handler=self.decode_qr,
            ),
            "analyze_qr_context": ToolSpec(
                name="analyze_qr_context",
                description=(
                    "Use the vision-language model to read all text around the QR code and describe "
                    "the surrounding claim (prize, refund, job, payment, etc.)."
                ),
                parameters={"type": "object", "properties": {}},
                handler=self.analyze_qr_context,
            ),
            "analyze_screenshot": ToolSpec(
                name="analyze_screenshot",
                description=(
                    "Use the vision-language model to OCR the screenshot and compare its visual identity, "
                    "login form and claims with the supplied brand/URL."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "brand_hint": {"type": "string"},
                        "claimed_url": {"type": "string"},
                    },
                },
                handler=self.analyze_screenshot,
            ),
            "compare_brand_reference": ToolSpec(
                name="compare_brand_reference",
                description=(
                    "Perceptually compare the screenshot with a local brand reference image (dHash). "
                    "Returns a similarity score or explains that no reference exists."
                ),
                parameters={
                    "type": "object",
                    "properties": {"brand_slug": {"type": "string"}},
                    "required": ["brand_slug"],
                },
                handler=self.compare_brand_reference,
            ),
            "parse_email": ToolSpec(
                name="parse_email",
                description=(
                    "Parse the uploaded EML: headers, Received hops, flags, body, URLs and safe static "
                    "attachment triage (no execution, no archive extraction)."
                ),
                parameters={"type": "object", "properties": {}},
                handler=self.parse_email,
            ),
            "verify_email_auth": ToolSpec(
                name="verify_email_auth",
                description=(
                    "Independently verify SPF against the originating IP, DKIM with dkimpy and DMARC "
                    "alignment using live DNS. Falls back to recorded Authentication-Results."
                ),
                parameters={"type": "object", "properties": {}},
                handler=self.verify_email_auth,
            ),
            "investigate_url": ToolSpec(
                name="investigate_url",
                description=(
                    "Fully investigate a URL: static structure, brand lookalikes, DNS, TLS, RDAP age, "
                    "threat intelligence, redirect chain and safe page inspection (forms, hidden text)."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "fetch_page": {"type": "boolean", "default": True},
                    },
                    "required": ["url"],
                },
                handler=self.investigate_url,
            ),
            "investigate_domain": ToolSpec(
                name="investigate_domain",
                description=(
                    "Investigate a domain without fetching a page: brand lookalikes, DNS, TLS, RDAP age "
                    "and threat-intelligence reputation."
                ),
                parameters={
                    "type": "object",
                    "properties": {"domain": {"type": "string"}},
                    "required": ["domain"],
                },
                handler=self.investigate_domain,
            ),
            "dns_lookup": ToolSpec(
                name="dns_lookup",
                description="Query A/AAAA/MX/NS/TXT records, SPF and DMARC for a domain.",
                parameters={
                    "type": "object",
                    "properties": {"domain": {"type": "string"}},
                    "required": ["domain"],
                },
                handler=self.dns_lookup,
            ),
            "tls_inspect": ToolSpec(
                name="tls_inspect",
                description="Inspect the TLS certificate chain, validity, issuer and expiry for a host.",
                parameters={
                    "type": "object",
                    "properties": {"host": {"type": "string"}, "port": {"type": "integer", "default": 443}},
                    "required": ["host"],
                },
                handler=self.tls_inspect,
            ),
            "rdap_lookup": ToolSpec(
                name="rdap_lookup",
                description="Look up domain registration age, registrar and status via RDAP.",
                parameters={
                    "type": "object",
                    "properties": {"domain": {"type": "string"}},
                    "required": ["domain"],
                },
                handler=self.rdap_lookup,
            ),
            "threat_intel_lookup": ToolSpec(
                name="threat_intel_lookup",
                description="Check a URL against configured threat-intelligence providers.",
                parameters={
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                },
                handler=self.threat_intel_lookup,
            ),
            "parse_upi": ToolSpec(
                name="parse_upi",
                description="Parse a UPI URI or VPA payment payload and explain the payment semantics.",
                parameters={
                    "type": "object",
                    "properties": {"payload": {"type": "string"}},
                    "required": ["payload"],
                },
                handler=self.parse_upi_tool,
            ),
            "local_ocr": ToolSpec(
                name="local_ocr",
                description="Run local Tesseract OCR if available (optional fallback for screenshots).",
                parameters={"type": "object", "properties": {}},
                handler=self.local_ocr,
            ),
        }
        return [registry[name] for name in names if name in registry]

    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        spec = next((item for item in self.specs([name])), None)
        if spec is None:
            raise ValueError(f"Unknown tool: {name}")
        return await spec.handler(arguments or {})

    # -------------------------------------------------------------- message
    async def analyze_message(self, args: dict[str, Any]) -> ToolResult:
        text = str(args.get("text") or "")
        if not text.strip():
            raise ValueError("Message text is empty")
        language = str(args.get("language") or "auto")
        channel = str(args.get("channel") or "sms")
        sender = args.get("sender")
        metadata = args.get("metadata") or {}
        analysis = analyze_message_text(
            text, language=language, channel=channel, sender=sender, metadata=metadata
        )
        text_evidence = self._add(
            EvidenceKind.MESSAGE_TEXT,
            f"Message text ({analysis.language}, {analysis.word_count} words)",
            {
                "text": truncate(text, 20_000),
                "sha256": sha256_text(text),
                "language": analysis.language,
                "script": analysis.script,
                "channel": channel,
                "sender": sender,
                "protective_phrases": analysis.protective_phrases[:5],
            },
            confidence=0.99,
            verified=True,
        )
        signal_evidence = self._add(
            EvidenceKind.MESSAGE_SIGNAL,
            f"Multilingual signal analysis: {len(analysis.signals)} indicator(s), "
            f"{len(analysis.scam_types)} scam hypothes(es)",
            {
                "scam_types": analysis.scam_types,
                "manipulation": analysis.manipulation,
                "notes": analysis.notes,
                "protective_phrases": analysis.protective_phrases,
                "language_confidence": analysis.language_confidence,
            },
            confidence=0.85,
            verified=True,
        )
        entity_evidence = self._add(
            EvidenceKind.ENTITY,
            "Extracted entities",
            analysis.entities,
            confidence=0.9,
            verified=True,
        )
        signals = []
        for signal in analysis.signals:
            signals.append(
                signal.model_copy(
                    update={
                        "evidence_ids": [signal_evidence.id],
                        "source": signal.source,
                    }
                )
            )
        iocs: list[IOC] = []
        for upi in analysis.entities.get("upi_ids", []):
            iocs.append(
                IOC(
                    type="upi_id",
                    value=upi,
                    risk=Severity.HIGH,
                    context="UPI address found in message",
                    evidence_ids=[entity_evidence.id],
                )
            )
        for phone in analysis.entities.get("phone_numbers", []):
            iocs.append(
                IOC(
                    type="phone",
                    value=phone,
                    risk=Severity.MEDIUM,
                    context="Sender/contact number in message",
                    evidence_ids=[entity_evidence.id],
                )
            )
        for email in analysis.entities.get("emails", []):
            iocs.append(
                IOC(
                    type="email",
                    value=email,
                    risk=Severity.MEDIUM,
                    context="Email address in message",
                    evidence_ids=[entity_evidence.id],
                )
            )
        return ToolResult(
            name="analyze_message",
            summary=(
                f"Detected {len(analysis.signals)} weighted indicator(s); "
                f"top hypothesis: {analysis.scam_types[0]['type'] if analysis.scam_types else 'none'}."
            ),
            evidence=[text_evidence, signal_evidence, entity_evidence],
            signals=signals,
            iocs=iocs,
            data={
                "language": analysis.language,
                "script": analysis.script,
                "scam_types": analysis.scam_types,
                "manipulation": analysis.manipulation,
                "entities": analysis.entities,
                "protective_phrases": analysis.protective_phrases,
                "notes": analysis.notes,
                "word_count": analysis.word_count,
            },
            pending_urls=analysis.entities.get("urls", []),
        )

    async def extract_urls_tool(self, args: dict[str, Any]) -> ToolResult:
        text = str(args.get("text") or "")
        extracted = extract_urls(text, limit=15)
        urls = dedupe([item.normalized for item in extracted])
        evidence = self._add(
            EvidenceKind.URL_REFERENCE,
            f"{len(urls)} URL(s) extracted from text",
            {"urls": [{"raw": item.raw, "normalized": item.normalized} for item in extracted]},
            confidence=0.98,
            verified=True,
        )
        return ToolResult(
            name="extract_urls",
            summary=f"Extracted {len(urls)} URL(s).",
            evidence=[evidence],
            data={"urls": urls},
            pending_urls=urls,
        )

    # ------------------------------------------------------------------- QR
    async def decode_qr(self, args: dict[str, Any]) -> ToolResult:
        image_bytes = self.artifacts.get("image_bytes")
        if not image_bytes:
            raise ValueError("No QR image was supplied")
        decoded = decode_qr_image(image_bytes)
        image_evidence = self._add(
            EvidenceKind.QR_IMAGE,
            (
                f"QR image {decoded['image']['width']}×{decoded['image']['height']} "
                f"({decoded['image']['format']}), sha256={decoded['image']['sha256'][:16]}…"
            ),
            decoded["image"],
            confidence=0.98,
            verified=True,
        )
        if not decoded["decoded"]:
            return ToolResult(
                name="decode_qr",
                summary="No QR payload could be decoded.",
                evidence=[image_evidence],
                data=decoded,
                notes=[decoded.get("warning") or "QR decode failed."],
            )

        inspections = []
        signals: list[Signal] = []
        iocs: list[IOC] = []
        pending_urls: list[str] = []
        for payload in decoded["payloads"]:
            info = inspect_payload(payload)
            inspections.append(info)
            if info["kind"] == "upi_payment":
                upi_evidence = self._add(
                    EvidenceKind.UPI_URI,
                    "UPI payment URI decoded from QR",
                    info,
                    confidence=0.97,
                    verified=True,
                )
                signals.extend(self._upi_signals(info, upi_evidence.id))
                if info.get("upi") and info["upi"].get("payee_vpa"):
                    iocs.append(
                        IOC(
                            type="upi_id",
                            value=info["upi"]["payee_vpa"],
                            risk=Severity.HIGH,
                            context="Payee VPA encoded in QR",
                            evidence_ids=[upi_evidence.id, image_evidence.id],
                        )
                    )
            elif info["kind"] in {"url", "text_with_url"}:
                pending_urls.extend(info.get("urls") or [])
                url_evidence = self._add(
                    EvidenceKind.URL_REFERENCE,
                    "URL encoded in QR code",
                    {"payload": payload, "urls": info.get("urls") or []},
                    confidence=0.97,
                    verified=True,
                )
                for url in info.get("urls") or []:
                    iocs.append(
                        IOC(
                            type="url",
                            value=url,
                            risk=Severity.HIGH,
                            context="Destination encoded in QR",
                            evidence_ids=[url_evidence.id],
                        )
                    )
            elif info["kind"] == "wifi":
                signals.append(
                    self._signal(
                        "qr_wifi",
                        "Wi-Fi configuration QR",
                        "The QR joins a Wi-Fi network. Open/unencrypted networks expose traffic to interception.",
                        12 if (info.get("wifi") or {}).get("risk") == "open" else 4,
                        Severity.HIGH if (info.get("wifi") or {}).get("risk") == "open" else Severity.LOW,
                        SignalCategory.INFRASTRUCTURE,
                        [image_evidence.id],
                    )
                )
            elif info["kind"] == "crypto_payment":
                signals.append(
                    self._signal(
                        "qr_crypto",
                        "Cryptocurrency payment QR",
                        "The QR requests an irreversible crypto transfer. Verify the recipient independently.",
                        16,
                        Severity.HIGH,
                        SignalCategory.PAYMENT,
                        [image_evidence.id],
                    )
                )
                crypto = info.get("crypto") or {}
                if crypto.get("address"):
                    iocs.append(
                        IOC(
                            type="crypto_wallet",
                            value=crypto["address"],
                            risk=Severity.HIGH,
                            context=f"{crypto.get('asset', 'crypto')} address encoded in QR",
                            evidence_ids=[image_evidence.id],
                        )
                    )
            elif info["kind"] == "otp_seed":
                signals.append(
                    self._signal(
                        "qr_otp_seed",
                        "2FA seed exposed in QR",
                        "A 2FA provisioning secret in a shared QR lets anyone clone the second factor.",
                        14,
                        Severity.HIGH,
                        SignalCategory.CONTENT,
                        [image_evidence.id],
                    )
                )
            elif info["kind"] == "structured_data":
                signals.append(
                    self._signal(
                        "qr_structured",
                        "Structured data payload",
                        "The QR contains structured data rather than a simple URL. Treat embedded instructions with suspicion.",
                        7,
                        Severity.MEDIUM,
                        SignalCategory.OBFUSCATION,
                        [image_evidence.id],
                    )
                )

        if len(decoded["payloads"]) > 1:
            signals.append(
                self._signal(
                    "qr_multiple_codes",
                    "Multiple QR codes in one image",
                    f"{len(decoded['payloads'])} payloads were found; an attacker may hide a second destination.",
                    6,
                    Severity.MEDIUM,
                    SignalCategory.OBFUSCATION,
                    [image_evidence.id],
                )
            )
        caption = str(self.artifacts.get("caption") or args.get("caption") or "")
        if caption and any(word in caption.lower() for word in ("receive", "refund", "cashback", "prize", "claim", "win")):
            if any(item["kind"] == "upi_payment" for item in inspections):
                signals.append(
                    self._signal(
                        "qr_receive_money_claim",
                        "QR paired with a 'receive money' claim",
                        f"The accompanying text says: “{truncate(caption, 160)}”. A UPI QR always debits the scanner.",
                        30,
                        Severity.CRITICAL,
                        SignalCategory.PAYMENT,
                        [image_evidence.id],
                    )
                )

        payload_evidence = self._add(
            EvidenceKind.QR_PAYLOAD,
            f"{len(decoded['payloads'])} QR payload(s) decoded and classified",
            {"decode_methods": decoded["methods"], "inspections": inspections},
            confidence=0.95,
            verified=True,
        )
        return ToolResult(
            name="decode_qr",
            summary=(
                f"Decoded {len(decoded['payloads'])} QR payload(s): "
                + ", ".join(item["kind"] for item in inspections)
            ),
            evidence=[image_evidence, payload_evidence],
            signals=signals,
            iocs=iocs,
            data={"decode": decoded, "inspections": inspections},
            pending_urls=dedupe(pending_urls),
        )

    def _upi_signals(self, info: dict[str, Any], evidence_id: str) -> list[Signal]:
        signals = [
            self._signal(
                "upi_payment_qr",
                "UPI payment instruction",
                "The QR payload is a UPI payment URI. Scanning/approving it transfers money *from* the scanner.",
                20,
                Severity.HIGH,
                SignalCategory.PAYMENT,
                [evidence_id],
            )
        ]
        for warning in info.get("warnings", []):
            lower = warning.lower()
            if "receive" in lower or "debit" in lower or "refund" in lower or "cashback" in lower:
                signals.append(
                    self._signal(
                        "upi_receive_lie",
                        "Contradictory 'receive money' claim",
                        warning,
                        28,
                        Severity.CRITICAL,
                        SignalCategory.PAYMENT,
                        [evidence_id],
                    )
                )
            elif "not in the known" in lower or "handle" in lower:
                signals.append(
                    self._signal(
                        "upi_unknown_handle",
                        "Unrecognised UPI handle",
                        warning,
                        10,
                        Severity.MEDIUM,
                        SignalCategory.PAYMENT,
                        [evidence_id],
                    )
                )
            elif "brand" in lower or "mentions" in lower:
                signals.append(
                    self._signal(
                        "upi_brand_mismatch",
                        "UPI payee name/brand mismatch",
                        warning,
                        18,
                        Severity.HIGH,
                        SignalCategory.IDENTITY,
                        [evidence_id],
                    )
                )
            elif "no payee" in lower or "payee address" in lower:
                signals.append(
                    self._signal(
                        "upi_missing_payee",
                        "UPI payee cannot be identified",
                        warning,
                        12,
                        Severity.HIGH,
                        SignalCategory.PAYMENT,
                        [evidence_id],
                    )
                )
        return signals

    async def parse_upi_tool(self, args: dict[str, Any]) -> ToolResult:
        payload = str(args.get("payload") or "")
        upi = parse_upi(payload)
        if upi is None:
            raise ValueError("Payload is not a UPI URI")
        info = {
            "payload": payload,
            "kind": "upi_payment",
            "upi": upi.model_dump(mode="json"),
            "warnings": upi.warnings,
        }
        evidence = self._add(
            EvidenceKind.UPI_URI,
            "UPI payment URI",
            info,
            confidence=0.97,
            verified=True,
        )
        return ToolResult(
            name="parse_upi",
            summary=f"UPI payment to {upi.payee_vpa or 'unknown payee'}.",
            evidence=[evidence],
            signals=self._upi_signals(info, evidence.id),
            data=info,
        )

    async def analyze_qr_context(self, args: dict[str, Any]) -> ToolResult:
        image_bytes = self.artifacts.get("image_bytes")
        if not image_bytes:
            raise ValueError("No QR image was supplied")
        if not self.llm.available:
            raise RuntimeError("Vision model is not configured")
        prepared, mime = prepare_for_vlm(self._open(image_bytes))
        prompt = """You are reading a QR-code screenshot for a fraud investigation.
Transcribe ALL visible text (OCR), then describe the surrounding claim and what the QR is asking the user to do.
Return ONLY JSON:
{
  "ocr_text": "full transcription",
  "caption": "surrounding marketing/instruction text",
  "asks_to_receive_money": true/false,
  "asks_to_pay": true/false,
  "claims_prize_or_refund": true/false,
  "brands_mentioned": ["..."],
  "payment_apps_mentioned": ["..."],
  "suspicious_instructions": ["..."],
  "summary": "one paragraph"
}"""
        parsed, _response = await self.llm.vision_json(
            "You are a precise forensic OCR and visual-context analyst. Never invent text.",
            prompt,
            [(prepared, mime)],
            max_tokens=1600,
        )
        if not parsed:
            raise RuntimeError("Vision model returned no usable JSON")
        ocr_text = str(parsed.get("ocr_text") or "")
        evidence = self._add(
            EvidenceKind.VLM_OBSERVATION,
            "Vision-language reading of QR screenshot context",
            parsed,
            confidence=0.8,
            verified=False,
        )
        if ocr_text:
            self._add(
                EvidenceKind.OCR_TEXT,
                "OCR text from QR screenshot",
                {"text": truncate(ocr_text, 8000), "sha256": sha256_text(ocr_text)},
                confidence=0.8,
                verified=False,
            )
        signals: list[Signal] = []
        if parsed.get("asks_to_receive_money") and parsed.get("payment_apps_mentioned"):
            signals.append(
                self._signal(
                    "qr_context_receive",
                    "Screenshot instructs users to 'receive money' via QR",
                    "A UPI QR debits the scanner; instructions promising an incoming payment are fraudulent.",
                    26,
                    Severity.CRITICAL,
                    SignalCategory.PAYMENT,
                    [evidence.id],
                    confidence=0.75,
                    source="vlm-context",
                )
            )
        if parsed.get("claims_prize_or_refund"):
            signals.append(
                self._signal(
                    "qr_context_prize",
                    "Prize/refund claim around QR",
                    "The screenshot associates the QR with a prize or refund, a classic lure.",
                    16,
                    Severity.HIGH,
                    SignalCategory.CONTENT,
                    [evidence.id],
                    confidence=0.7,
                    source="vlm-context",
                )
            )
        return ToolResult(
            name="analyze_qr_context",
            summary=str(parsed.get("summary") or "Visual context analysed."),
            evidence=[evidence],
            signals=signals,
            data={"vision": parsed},
            notes=[str(item) for item in (parsed.get("suspicious_instructions") or [])][:5],
        )

    @staticmethod
    def _open(image_bytes: bytes):
        import io

        from PIL import Image

        return Image.open(io.BytesIO(image_bytes))

    # --------------------------------------------------------------- visual
    async def analyze_screenshot(self, args: dict[str, Any]) -> ToolResult:
        image_bytes = self.artifacts.get("image_bytes")
        if not image_bytes:
            raise ValueError("No screenshot was supplied")
        brand_hint = str(args.get("brand_hint") or self.artifacts.get("brand_hint") or "")
        claimed_url = str(args.get("claimed_url") or self.artifacts.get("claimed_url") or "")
        image = self._open(image_bytes)
        prepared, mime = prepare_for_vlm(image)
        image_evidence = self._add(
            EvidenceKind.IMAGE,
            f"Screenshot {image.width}×{image.height} ({image.format})",
            {
                **basic_image_evidence(image_bytes),
                "brand_hint": brand_hint,
                "claimed_url": claimed_url,
            },
            confidence=0.99,
            verified=True,
        )
        if not self.llm.available:
            ocr = try_local_ocr(image_bytes)
            if ocr.get("available"):
                self._add(
                    EvidenceKind.OCR_TEXT,
                    "Local OCR transcription (vision model unavailable)",
                    {"text": ocr["text"], "engine": ocr["engine"]},
                    confidence=0.65,
                    verified=False,
                )
            return ToolResult(
                name="analyze_screenshot",
                summary="Vision model unavailable; only image metadata/local OCR was collected.",
                evidence=[image_evidence],
                data={"brand_hint": brand_hint, "claimed_url": claimed_url, "local_ocr": ocr},
                pending_urls=[
                    claimed_url
                ] if claimed_url.startswith(("http://", "https://")) else [],
                notes=["Set HF_TOKEN and LLM_MODE=huggingface for visual reasoning."],
            )

        prompt = f"""Analyse this website screenshot as a brand-impersonation investigator.
Context supplied by the user: brand_hint={brand_hint or 'none'}, claimed_url={claimed_url or 'none'}.
Tasks:
1. OCR all visible text, especially the address bar, logo wordmark, headings, form labels and error/urgency messages.
2. Identify the brand the page appears to claim (logo shapes, colours, wordmark, layout).
3. Identify login/credential fields (email, password, OTP, card, CVV, UPI PIN, Aadhaar, PAN).
4. Note visual inconsistencies, spelling errors, low-quality logos, mismatched branding, unusual payment requests.
5. Decide whether the page shows signs of brand impersonation or credential phishing.
Return ONLY valid JSON:
{{
  "brand_guess": "string or null",
  "claims_brand": true/false,
  "ocr_text": "full transcription",
  "page_title": "string or null",
  "observed_url": "string or null",
  "visual_identity": {{"logos": [], "colors": [], "layout": "description"}},
  "login_form": {{"present": true/false, "fields": [], "suspicious": true/false}},
  "inconsistencies": ["..."],
  "phishing_indicators": ["..."],
  "impersonation_confidence": 0.0,
  "summary": "one paragraph"
}}"""
        parsed, _response = await self.llm.vision_json(
            "You are a meticulous visual forensics analyst. Base every statement on visible pixels. "
            "If the address bar is unreadable, say so instead of guessing.",
            prompt,
            [(prepared, mime)],
            max_tokens=2200,
        )
        if not parsed:
            raise RuntimeError("Vision model returned no usable JSON")
        vlm_evidence = self._add(
            EvidenceKind.VLM_OBSERVATION,
            "Vision-language website impersonation analysis",
            parsed,
            confidence=0.82,
            verified=False,
        )
        ocr_text = str(parsed.get("ocr_text") or "")
        if ocr_text:
            self._add(
                EvidenceKind.OCR_TEXT,
                "OCR transcription from screenshot",
                {"text": truncate(ocr_text, 12_000), "sha256": sha256_text(ocr_text)},
                confidence=0.8,
                verified=False,
            )
        signals: list[Signal] = []
        confidence = float(parsed.get("impersonation_confidence") or 0)
        if parsed.get("claims_brand") and confidence >= 0.55:
            signals.append(
                self._signal(
                    "visual_impersonation",
                    "Visual brand impersonation indicators",
                    f"Vision model confidence {int(confidence * 100)}% that the page imitates "
                    f"{parsed.get('brand_guess') or brand_hint or 'a brand'}.",
                    22 if confidence < 0.8 else 30,
                    Severity.HIGH if confidence < 0.8 else Severity.CRITICAL,
                    SignalCategory.VISUAL,
                    [vlm_evidence.id],
                    confidence=min(0.95, max(0.5, confidence)),
                    source="vlm",
                )
            )
        login_form = parsed.get("login_form") or {}
        if login_form.get("present") and login_form.get("suspicious"):
            signals.append(
                self._signal(
                    "visual_login_form",
                    "Suspicious credential form",
                    "The page shows a login/credential form with fields: "
                    + ", ".join(str(item) for item in login_form.get("fields", [])[:8]),
                    18,
                    Severity.HIGH,
                    SignalCategory.VISUAL,
                    [vlm_evidence.id],
                    confidence=0.8,
                    source="vlm",
                )
            )
        inconsistencies = parsed.get("inconsistencies") or []
        if inconsistencies:
            signals.append(
                self._signal(
                    "visual_inconsistencies",
                    "Brand inconsistencies detected",
                    "; ".join(str(item) for item in inconsistencies[:5]),
                    10,
                    Severity.MEDIUM,
                    SignalCategory.VISUAL,
                    [vlm_evidence.id],
                    confidence=0.75,
                    source="vlm",
                )
            )
        if parsed.get("phishing_indicators"):
            signals.append(
                self._signal(
                    "visual_phishing_cues",
                    "Visual phishing cues",
                    "; ".join(str(item) for item in parsed["phishing_indicators"][:5]),
                    10,
                    Severity.MEDIUM,
                    SignalCategory.VISUAL,
                    [vlm_evidence.id],
                    confidence=0.72,
                    source="vlm",
                )
            )
        observed_url = str(parsed.get("observed_url") or "")
        pending = [
            item
            for item in (observed_url, claimed_url)
            if item.startswith(("http://", "https://"))
        ]
        return ToolResult(
            name="analyze_screenshot",
            summary=str(parsed.get("summary") or "Screenshot analysed."),
            evidence=[image_evidence, vlm_evidence],
            signals=signals,
            data={"vision": parsed, "brand_hint": brand_hint, "claimed_url": claimed_url},
            pending_urls=pending,
        )

    async def compare_brand_reference(self, args: dict[str, Any]) -> ToolResult:
        image_bytes = self.artifacts.get("image_bytes")
        if not image_bytes:
            raise ValueError("No screenshot was supplied")
        slug = str(args.get("brand_slug") or "")
        comparison = compare_with_reference(image_bytes, slug)
        evidence = self._add(
            EvidenceKind.IMAGE_SIMILARITY,
            (
                f"Perceptual comparison with '{slug}' reference: "
                + (
                    f"{comparison.get('similarity', 0):.2f} similarity"
                    if comparison.get("available")
                    else comparison.get("reason", "unavailable")
                )
            ),
            comparison,
            confidence=0.75 if comparison.get("available") else 0.3,
            verified=bool(comparison.get("available")),
        )
        return ToolResult(
            name="compare_brand_reference",
            summary=str(comparison.get("interpretation") or comparison.get("reason") or ""),
            evidence=[evidence],
            data={"comparison": comparison},
        )

    async def local_ocr(self, args: dict[str, Any]) -> ToolResult:
        image_bytes = self.artifacts.get("image_bytes")
        if not image_bytes:
            raise ValueError("No image was supplied")
        ocr = try_local_ocr(image_bytes)
        evidence = self._add(
            EvidenceKind.OCR_TEXT,
            "Local OCR transcription",
            ocr,
            confidence=0.65 if ocr.get("available") else 0.2,
            verified=False,
        )
        return ToolResult(
            name="local_ocr",
            summary=("OCR complete." if ocr.get("available") else "Local OCR unavailable."),
            evidence=[evidence],
            data={"ocr": ocr},
        )

    # ---------------------------------------------------------------- email
    async def parse_email(self, args: dict[str, Any]) -> ToolResult:
        raw = self.artifacts.get("eml_bytes")
        if not raw:
            raise ValueError("No EML content was supplied")
        parsed = parse_email_engine(raw)
        self.artifacts["parsed_email"] = parsed
        headers_evidence = self._add(
            EvidenceKind.EMAIL_HEADERS,
            f"Email headers: From {parsed.get('from_address')} / Reply-To {parsed.get('reply_to_address') or 'none'}",
            {
                "subject": parsed["subject"],
                "from_display": parsed["from_display"],
                "from_address": parsed["from_address"],
                "from_domain": parsed["from_domain"],
                "reply_to_address": parsed["reply_to_address"],
                "return_path": parsed["return_path"],
                "message_id": parsed["message_id"],
                "to": parsed["to"],
                "headers": parsed["headers"],
                "received": parsed["received"],
                "auth_header_claims": parsed["auth_results"],
                "received_spf": parsed["received_spf"],
                "dkim_signatures": parsed["dkim_signatures"],
                "raw_sha256": parsed["raw_sha256"],
                "raw_size": parsed["raw_size"],
            },
            confidence=0.98,
            verified=True,
        )
        hop_evidence = self._add(
            EvidenceKind.EMAIL_HOP,
            f"Received chain with {len(parsed['received'])} hop(s)",
            {"hops": parsed["received"]},
            confidence=0.9,
            verified=True,
        )
        body_evidence = self._add(
            EvidenceKind.EMAIL_BODY,
            f"Email body: {len(parsed['body_text'])} characters, {parsed['url_count']} URL(s)",
            {
                "body_preview": parsed["body_preview"],
                "body_sha256": sha256_text(parsed["body_text"]),
                "html_present": parsed["html_present"],
                "html_analysis": parsed["html_analysis"],
                "urls": parsed["urls"],
                "has_list_unsubscribe": parsed["has_list_unsubscribe"],
            },
            confidence=0.95,
            verified=True,
        )
        attachment_evidence = []
        for attachment in parsed["attachments"]:
            ev = self._add(
                EvidenceKind.EMAIL_ATTACHMENT,
                f"Attachment '{attachment['filename']}' ({attachment['content_type']}, {attachment['size']} bytes)",
                attachment,
                confidence=0.9,
                verified=True,
            )
            attachment_evidence.append(ev)
        auth_header_evidence = self._add(
            EvidenceKind.EMAIL_AUTH,
            "Authentication-Results / Received-SPF header claims",
            {
                "authentication_results": parsed["auth_results"],
                "received_spf": parsed["received_spf"],
                "live_verified": False,
            },
            confidence=0.7,
            verified=False,
        )
        signals: list[Signal] = []
        attachment_ids = [item.id for item in attachment_evidence]
        for flag in parsed["flags"]:
            category = SignalCategory(flag["category"])
            if flag["id"] in {"risky_attachment", "invoice_attachment"}:
                refs = attachment_ids[:1] or [body_evidence.id]
            elif category in {SignalCategory.IDENTITY, SignalCategory.OBFUSCATION, SignalCategory.INFRASTRUCTURE, SignalCategory.AUTH}:
                refs = [headers_evidence.id]
            elif category == SignalCategory.PAYMENT:
                refs = [body_evidence.id]
            else:
                refs = [body_evidence.id]
            signals.append(
                self._signal(
                    flag["id"],
                    flag["label"],
                    flag["detail"],
                    int(flag["weight"]),
                    Severity(flag["severity"]),
                    category,
                    refs,
                    confidence=0.85,
                    source="email-parser",
                )
            )
        pending_domains = dedupe(
            [
                domain
                for domain in (
                    parsed.get("from_domain"),
                    parsed.get("reply_to_domain"),
                    parsed.get("return_domain"),
                    parsed.get("message_id_domain"),
                )
                if domain and domain not in FREE_MAIL_DOMAINS
            ]
        )
        iocs: list[IOC] = []
        for address, label in (
            (parsed.get("from_address"), "From address"),
            (parsed.get("reply_to_address"), "Reply-To address"),
            (parsed.get("return_path"), "Return-Path"),
        ):
            if address:
                iocs.append(
                    IOC(
                        type="email",
                        value=address,
                        risk=Severity.HIGH,
                        context=label,
                        evidence_ids=[headers_evidence.id],
                    )
                )
        for hop in parsed["received"]:
            if hop.get("ip"):
                iocs.append(
                    IOC(
                        type="ip",
                        value=hop["ip"],
                        risk=Severity.MEDIUM,
                        context="Received-chain hop",
                        evidence_ids=[hop_evidence.id],
                    )
                )
        for attachment in parsed["attachments"]:
            iocs.append(
                IOC(
                    type="file_hash",
                    value=attachment["sha256"],
                    risk=Severity.HIGH if attachment["flags"] else Severity.MEDIUM,
                    context=f"Attachment {attachment['filename']}",
                    evidence_ids=[item.id for item in attachment_evidence],
                )
            )
        return ToolResult(
            name="parse_email",
            summary=(
                f"Parsed email from {parsed['from_address']} with {len(parsed['attachments'])} attachment(s), "
                f"{parsed['url_count']} URL(s), and {len(parsed['flags'])} header/body flag(s)."
            ),
            evidence=[headers_evidence, hop_evidence, body_evidence, auth_header_evidence, *attachment_evidence],
            signals=signals,
            iocs=iocs,
            data={
                "subject": parsed["subject"],
                "from": parsed["from_address"],
                "from_domain": parsed["from_domain"],
                "reply_to": parsed["reply_to_address"],
                "return_path": parsed["return_path"],
                "message_id": parsed["message_id"],
                "auth_results": parsed["auth_results"],
                "flags": parsed["flags"],
                "body_preview": parsed["body_preview"],
                "body_text": truncate(parsed["body_text"], 12_000),
                "urls": parsed["urls"],
                "attachments": [
                    {key: value for key, value in item.items() if key not in {"details"}}
                    for item in parsed["attachments"]
                ],
                "attachment_details": [item.get("details", {}) for item in parsed["attachments"]],
                "received": parsed["received"],
                "html_present": parsed["html_present"],
                "entities": {
                    "from_address": parsed["from_address"],
                    "reply_to": parsed["reply_to_address"],
                    "domains": dedupe([parsed["from_domain"], parsed["reply_to_domain"], parsed["return_domain"]]),
                },
            },
            pending_urls=[item["url"] for item in parsed["urls"]],
            pending_domains=pending_domains,
        )

    async def verify_email_auth(self, args: dict[str, Any]) -> ToolResult:
        raw = self.artifacts.get("eml_bytes")
        parsed = self.artifacts.get("parsed_email")
        if not raw or not parsed:
            raise ValueError("parse_email must run before verify_email_auth")
        auth = await verify_email_auth_engine(raw, parsed, self.settings, self.services.dns)
        live = auth.get("enabled", False)
        evidence = self._add(
            EvidenceKind.EMAIL_AUTH,
            "Live email authentication verification" if live else "Recorded email authentication claims",
            auth,
            confidence=0.95 if live else 0.65,
            verified=live,
            notes=[auth.get("summary", "")],
        )
        signals: list[Signal] = []
        spf = (auth.get("spf") or {}).get("result")
        dkim = (auth.get("dkim") or {}).get("result")
        dmarc = (auth.get("dmarc") or {}).get("result")
        if spf == "fail":
            signals.append(self._signal("live_spf_fail", "SPF failed", (auth.get("spf") or {}).get("explanation", "SPF failed."), 16, Severity.HIGH, SignalCategory.AUTH, [evidence.id]))
        elif spf == "softfail":
            signals.append(self._signal("live_spf_softfail", "SPF soft-failed", (auth.get("spf") or {}).get("explanation", "SPF soft-failed."), 9, Severity.MEDIUM, SignalCategory.AUTH, [evidence.id]))
        if dkim == "fail":
            signals.append(self._signal("live_dkim_fail", "DKIM failed", "; ".join((auth.get("dkim") or {}).get("errors", [])) or "DKIM signature invalid.", 12, Severity.HIGH, SignalCategory.AUTH, [evidence.id]))
        if dmarc == "fail":
            signals.append(self._signal("live_dmarc_fail", "DMARC failed", (auth.get("dmarc") or {}).get("explanation", "DMARC failed."), 20, Severity.HIGH, SignalCategory.AUTH, [evidence.id]))
        if (auth.get("dmarc") or {}).get("result") == "none" and live:
            signals.append(self._signal("no_dmarc", "Sender domain has no DMARC policy", "The From domain publishes no DMARC record, so receivers cannot enforce alignment.", 4, Severity.LOW, SignalCategory.AUTH, [evidence.id], confidence=0.9))
        header_spf = (parsed.get("auth_results") or {}).get("spf")
        header_dmarc = (parsed.get("auth_results") or {}).get("dmarc")
        if live and header_spf == "pass" and spf in {"fail", "softfail"}:
            signals.append(self._signal("auth_header_conflict_spf", "SPF header conflicts with live DNS", f"Receiver header claimed SPF pass, but live evaluation returned {spf}.", 14, Severity.HIGH, SignalCategory.AUTH, [evidence.id]))
        if live and header_dmarc == "pass" and dmarc == "fail":
            signals.append(self._signal("auth_header_conflict_dmarc", "DMARC header conflicts with live DNS", "Receiver header claimed DMARC pass, but independent alignment failed.", 16, Severity.HIGH, SignalCategory.AUTH, [evidence.id]))
        return ToolResult(
            name="verify_email_auth",
            summary=auth.get("summary", "Authentication verification complete."),
            evidence=[evidence],
            signals=signals,
            data={"auth": auth},
        )

    # ------------------------------------------------------------------ url
    async def investigate_url(self, args: dict[str, Any]) -> ToolResult:
        url = normalize_url(str(args.get("url") or ""))
        fetch_page = bool(args.get("fetch_page", True))
        result = await self.services.urls.investigate(url, fetch_page=fetch_page)
        return self._url_investigation_result(result, source_kind="url")

    async def investigate_domain(self, args: dict[str, Any]) -> ToolResult:
        domain = str(args.get("domain") or "").strip().lower()
        if not domain:
            raise ValueError("domain is required")
        result = await self.services.urls.investigate(
            f"https://{domain}/", fetch_page=False
        )
        return self._url_investigation_result(result, source_kind="domain")

    def _url_investigation_result(self, result: dict[str, Any], *, source_kind: str) -> ToolResult:
        static = result["static"]
        model = result["model"]
        static_ev = self._add(
            EvidenceKind.URL_STATIC,
            f"Static URL analysis: score {result['reputation_score']}/100, verdict {result['verdict'].value}",
            static,
            confidence=0.9,
            verified=True,
        )
        dns_ev = None
        if result.get("dns"):
            dns_ev = self._add(
                EvidenceKind.DNS,
                f"DNS records for {result.get('normalized_url')}",
                result["dns"],
                confidence=0.9,
                verified=bool(not (result["dns"].get("errors") or [])),
                notes=result["dns"].get("errors") or [],
            )
        ssl_ev = None
        if result.get("ssl"):
            tls_label, tls_confidence, tls_verified = _tls_evidence_meta(result["ssl"])
            ssl_ev = self._add(
                EvidenceKind.SSL,
                (
                    "TLS certificate: "
                    + tls_label
                    + (f", {result['ssl'].get('days_remaining')} days remaining" if result["ssl"].get("days_remaining") is not None else "")
                ),
                result["ssl"],
                confidence=tls_confidence,
                verified=tls_verified,
                notes=[result["ssl"].get("error") or ""],
            )
        rdap_ev = None
        if result.get("rdap") and result["rdap"].get("available"):
            rdap_ev = self._add(
                EvidenceKind.RDAP,
                f"RDAP registration age: {result['rdap'].get('age_days')} days",
                result["rdap"],
                confidence=0.9,
                verified=True,
            )
        fetch_ev = None
        if result.get("page", {}).get("available"):
            fetch_ev = self._add(
                EvidenceKind.URL_FETCH,
                f"Safe page fetch: HTTP {result['page'].get('status')}, title '{((result['page'].get('html') or {}).get('title') or '')[:80]}'",
                result["page"],
                confidence=0.88,
                verified=True,
            )
        intel_ev = self._add(
            EvidenceKind.THREAT_INTEL,
            "Threat-intelligence correlation: "
            + ", ".join(f"{item['source']}={item['status']}" for item in result["threat_intel"][:6]),
            {"sources": result["threat_intel"]},
            confidence=0.85,
            verified=any(
                item["status"] in {"clean", "suspicious", "malicious"}
                for item in result["threat_intel"]
            ),
        )
        signals: list[Signal] = []
        for url_signal in model.signals:
            identifier = url_signal.id
            if identifier.startswith("ti_"):
                ref = intel_ev.id
            elif identifier in {"invalid_tls", "expired_tls"}:
                ref = ssl_ev.id if ssl_ev else static_ev.id
            elif identifier in {"very_new_domain", "new_domain"}:
                ref = rdap_ev.id if rdap_ev else static_ev.id
            elif identifier in {
                "password_form_unofficial", "external_form_target", "link_text_mismatch",
                "hidden_page_text", "script_obfuscation", "page_download_links", "redirect_destination",
            }:
                ref = fetch_ev.id if fetch_ev else static_ev.id
            elif identifier.startswith(("no_dns",)):
                ref = dns_ev.id if dns_ev else static_ev.id
            else:
                ref = static_ev.id
            signals.append(
                Signal(
                    id=url_signal.id,
                    category=url_signal.category,
                    label=url_signal.label,
                    description=url_signal.detail,
                    weight=url_signal.weight,
                    severity=url_signal.severity,
                    evidence_ids=[ref],
                    confidence=0.9,
                    source=f"url-investigator:{source_kind}",
                )
            )
        iocs: list[IOC] = []
        for domain in result["iocs"].get("domains", []):
            if domain:
                iocs.append(
                    IOC(
                        type="domain",
                        value=domain,
                        risk=Severity.HIGH if model.verdict in {Verdict.MALICIOUS, Verdict.LIKELY_MALICIOUS} else Severity.MEDIUM,
                        context=f"Domain from {source_kind} investigation",
                        evidence_ids=[static_ev.id],
                    )
                )
        for ip in result["iocs"].get("ips", []):
            iocs.append(
                IOC(
                    type="ip",
                    value=ip,
                    risk=Severity.HIGH if model.verdict == Verdict.MALICIOUS else Severity.MEDIUM,
                    context="Resolved address",
                    evidence_ids=[dns_ev.id] if dns_ev else [static_ev.id],
                )
            )
        for url in result["iocs"].get("urls", []):
            if url:
                iocs.append(
                    IOC(
                        type="url",
                        value=url,
                        risk=Severity.HIGH if model.verdict in {Verdict.MALICIOUS, Verdict.LIKELY_MALICIOUS} else Severity.MEDIUM,
                        context="Investigated URL",
                        evidence_ids=[static_ev.id],
                    )
                )
        evidence = [static_ev]
        evidence.extend(item for item in (dns_ev, ssl_ev, rdap_ev, fetch_ev, intel_ev) if item)
        return ToolResult(
            name="investigate_url" if source_kind == "url" else "investigate_domain",
            summary=result["summary"],
            evidence=evidence,
            signals=signals,
            iocs=iocs,
            data={
                "normalized_url": result["normalized_url"],
                "final_url": result["final_url"],
                "host": result["static"]["host"],
                "registered_domain": result["static"]["registered_domain"],
                "verdict": model.verdict.value,
                "reputation_score": model.reputation_score,
                "signals": [signal.model_dump(mode="json") for signal in model.signals],
                "dns": {
                    "a": (result.get("dns") or {}).get("a", []),
                    "mx": (result.get("dns") or {}).get("mx", []),
                    "spf": (result.get("dns") or {}).get("spf"),
                    "dmarc_policy": (result.get("dns") or {}).get("dmarc_policy"),
                },
                "ssl": {
                    "valid": (result.get("ssl") or {}).get("valid"),
                    "inspected": (result.get("ssl") or {}).get("inspected", True),
                    "issuer": (result.get("ssl") or {}).get("issuer"),
                    "days_remaining": (result.get("ssl") or {}).get("days_remaining"),
                    "error": (result.get("ssl") or {}).get("error"),
                },
                "rdap": result.get("rdap"),
                "threat_intel": [
                    {
                        "source": item["source"],
                        "status": item["status"],
                        "detail": item["detail"],
                    }
                    for item in result["threat_intel"]
                ],
                "page": result.get("page", {}).get("html", {}),
                "notes": result.get("notes", []),
            },
        )

    async def dns_lookup(self, args: dict[str, Any]) -> ToolResult:
        domain = str(args.get("domain") or "").strip().lower()
        info = await self.services.dns.lookup(domain)
        evidence = self._add(
            EvidenceKind.DNS,
            f"DNS lookup for {domain}",
            info.model_dump(mode="json"),
            confidence=0.9,
            verified=bool(not info.errors),
            notes=info.errors,
        )
        return ToolResult(
            name="dns_lookup",
            summary=f"DNS lookup completed for {domain}.",
            evidence=[evidence],
            data={"dns": info.model_dump(mode="json")},
        )

    async def tls_inspect(self, args: dict[str, Any]) -> ToolResult:
        host = str(args.get("host") or "").strip().lower()
        port = int(args.get("port") or 443)
        info = await self.services.tls.inspect(host, port)
        payload = info.model_dump(mode="json")
        label, confidence, verified = _tls_evidence_meta(payload)
        evidence = self._add(
            EvidenceKind.SSL,
            f"TLS inspection for {host}: {label}",
            payload,
            confidence=confidence,
            verified=verified,
            notes=[info.error] if info.error else [],
        )
        return ToolResult(
            name="tls_inspect",
            summary=f"TLS certificate {label} for {host}.",
            evidence=[evidence],
            data={"tls": payload},
        )

    async def rdap_lookup(self, args: dict[str, Any]) -> ToolResult:
        domain = str(args.get("domain") or "").strip().lower()
        info = await self.services.rdap.lookup(domain)
        evidence = self._add(
            EvidenceKind.RDAP,
            f"RDAP lookup for {domain}",
            info,
            confidence=0.85,
            verified=bool(info.get("available")),
        )
        return ToolResult(
            name="rdap_lookup",
            summary=f"RDAP lookup {'completed' if info.get('available') else 'unavailable'}.",
            evidence=[evidence],
            data={"rdap": info},
        )

    async def threat_intel_lookup(self, args: dict[str, Any]) -> ToolResult:
        url = str(args.get("url") or "")
        host = (urlsplit(normalize_url(url)).hostname or "").lower()
        domain = registrable_domain(host)
        results = await self.services.intel.check_url(url, domain, [])
        evidence = self._add(
            EvidenceKind.THREAT_INTEL,
            "Threat-intelligence lookup: " + ", ".join(f"{item.source}={item.status}" for item in results[:6]),
            {"sources": [item.model_dump(mode="json") for item in results]},
            confidence=0.85,
            verified=any(item.status in {"clean", "suspicious", "malicious"} for item in results),
        )
        signals = []
        for item in results:
            if item.status == "malicious":
                signals.append(self._signal(f"ti_{item.source}", f"Threat intelligence match: {item.source}", item.detail, 40, Severity.CRITICAL, SignalCategory.THREAT_INTEL, [evidence.id]))
            elif item.status == "suspicious":
                signals.append(self._signal(f"ti_{item.source}", f"Suspicious reputation: {item.source}", item.detail, 22, Severity.HIGH, SignalCategory.THREAT_INTEL, [evidence.id]))
        return ToolResult(
            name="threat_intel_lookup",
            summary=", ".join(f"{item.source}={item.status}" for item in results),
            evidence=[evidence],
            signals=signals,
            data={"threat_intel": [item.model_dump(mode="json") for item in results]},
        )
