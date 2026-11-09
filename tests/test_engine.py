"""Focused tests for the transparent engine primitives."""

from __future__ import annotations

from app.engine.brands import get_brand_registry
from app.engine.risk import RiskEngine
from app.engine.text_signals import analyze_message_text
from app.engine.urls import analyze_url_static, parse_upi_uri
from app.schemas import Evidence, EvidenceKind, Severity, Signal, SignalCategory


def _evidence() -> Evidence:
    return Evidence(
        id="ev_unit",
        kind=EvidenceKind.MESSAGE_SIGNAL,
        source="unit-test",
        summary="unit evidence",
        verified=True,
    )


def test_risk_category_caps_are_applied():
    signals = [
        Signal(
            id="identity_a",
            category=SignalCategory.IDENTITY,
            label="Identity A",
            description="identity signal",
            weight=30,
            severity=Severity.HIGH,
            evidence_ids=["ev_unit"],
        ),
        Signal(
            id="identity_b",
            category=SignalCategory.IDENTITY,
            label="Identity B",
            description="identity signal",
            weight=30,
            severity=Severity.HIGH,
            evidence_ids=["ev_unit"],
        ),
    ]
    risk = RiskEngine().assess(signals, [_evidence()], module="message")
    assert risk.category_scores["identity"] == 30
    assert risk.score == 30
    assert risk.verdict.value == "suspicious"


def test_risk_combo_cannot_exceed_category_cap():
    signals = [
        Signal(
            id="identity_a",
            category=SignalCategory.IDENTITY,
            label="Identity A",
            description="identity signal",
            weight=30,
            severity=Severity.HIGH,
            evidence_ids=["ev_unit"],
        ),
        Signal(
            id="identity_b",
            category=SignalCategory.IDENTITY,
            label="Identity B",
            description="identity signal",
            weight=30,
            severity=Severity.HIGH,
            evidence_ids=["ev_unit"],
        ),
        Signal(
            id="identity_c",
            category=SignalCategory.IDENTITY,
            label="Identity C",
            description="identity signal",
            weight=30,
            severity=Severity.HIGH,
            evidence_ids=["ev_unit"],
        ),
    ]
    risk = RiskEngine().assess(signals, [_evidence()], module="message")
    assert risk.category_scores["identity"] == 30
    # The only extra points come from the multiple-high-indicators combo,
    # which is capped under CONTENT (24), never by breaking the identity cap.
    assert risk.score == 35


def test_multilingual_detection_and_otp_tactics():
    samples = {
        "hinglish": "Aapka account block ho gaya hai, turant OTP share karein",
        "hi": "आपका खाता बंद हो गया है, तुरंत OTP भेजें",
        "bn": "আপনার অ্যাকাউন্ট বন্ধ হয়ে গেছে, এখনই OTP দিন",
    }
    for language, text in samples.items():
        result = analyze_message_text(text, language="auto")
        assert result.language == language
        tactics = {item["tactic"] for item in result.manipulation}
        assert "otp_request" in tactics, (language, tactics)
        assert any(
            item["type"] in {"phishing", "otp_theft"} for item in result.scam_types
        ), (language, result.scam_types)


def test_protective_phrase_is_not_flagged_as_otp_theft():
    result = analyze_message_text("Never share your OTP with anyone, even bank staff.")
    tactics = {item["tactic"] for item in result.manipulation}
    assert "otp_request" not in tactics
    assert result.protective_phrases


def test_url_static_detects_brand_in_subdomain():
    result = analyze_url_static("https://paypal.com.verify-account.xyz/login")
    assert result.registered_domain == "verify-account.xyz"
    assert result.brand_match is not None
    labels = " ".join(signal.label for signal in result.signals).lower()
    assert "brand" in labels


def test_upi_refund_lie_is_explained():
    info = parse_upi_uri(
        "upi://pay?pa=scammer@upi&pn=Refund%20Officer&am=4999&cu=INR&tn=Refund"
    )
    assert info.payee_vpa == "scammer@upi"
    assert info.amount == "4999"
    assert any("debits" in warning.lower() for warning in info.warnings)


def test_brand_registry_official_domain():
    registry = get_brand_registry()
    assert registry.is_official("www.sbi.co.in")
    assert not registry.is_official("sbi-secure-login.xyz")
