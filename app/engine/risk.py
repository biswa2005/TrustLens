"""Explainable, evidence-weighted risk assessment.

This is intentionally *not* a machine-learning classifier.  It is an additive,
auditable scoring model with category caps and explicit combination rules.  The
LLM may explain or prioritise the result, but it cannot silently change the
score without adding a referenced signal.
"""

from __future__ import annotations

from collections import defaultdict

from app.engine.utils import clamp
from app.schemas import (
    Evidence,
    RiskAssessment,
    RiskFactor,
    Severity,
    Signal,
    SignalCategory,
    Verdict,
)

CATEGORY_CAPS: dict[SignalCategory, int] = {
    SignalCategory.IDENTITY: 30,
    SignalCategory.PAYMENT: 32,
    SignalCategory.PRESSURE: 16,
    SignalCategory.LINK: 30,
    SignalCategory.THREAT_INTEL: 45,
    SignalCategory.AUTH: 40,
    SignalCategory.VISUAL: 30,
    SignalCategory.CONTENT: 24,
    SignalCategory.OBFUSCATION: 12,
    SignalCategory.INFRASTRUCTURE: 24,
}

SEVERITY_THRESHOLDS = (
    (80, Severity.CRITICAL),
    (60, Severity.HIGH),
    (40, Severity.MEDIUM),
    (20, Severity.LOW),
    (0, Severity.INFO),
)


def _verdict(score: int, inconclusive: bool) -> Verdict:
    if inconclusive:
        return Verdict.INCONCLUSIVE
    if score >= 70:
        return Verdict.MALICIOUS
    if score >= 45:
        return Verdict.LIKELY_MALICIOUS
    if score >= 20:
        return Verdict.SUSPICIOUS
    return Verdict.BENIGN


def _severity(score: int) -> Severity:
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.INFO


def _combo_rules(signals: list[Signal], category_ids: dict[str, set[str]]) -> list[Signal]:
    combos: list[Signal] = []
    identity = {item.lower() for item in category_ids.get(SignalCategory.IDENTITY, set())}
    payment = {item.lower() for item in category_ids.get(SignalCategory.PAYMENT, set())}
    pressure = {item.lower() for item in category_ids.get(SignalCategory.PRESSURE, set())}
    visual = {item.lower() for item in category_ids.get(SignalCategory.VISUAL, set())}
    auth = {item.lower() for item in category_ids.get(SignalCategory.AUTH, set())}
    content = {item.lower() for item in category_ids.get(SignalCategory.CONTENT, set())}
    credential_lure = any("credential_lure" in item for item in content)

    def add(identifier: str, label: str, detail: str, weight: int, category: SignalCategory) -> None:
        combos.append(
            Signal(
                id=identifier,
                category=category,
                label=label,
                description=detail,
                weight=weight,
                severity=Severity.HIGH,
                evidence_ids=[],
                confidence=0.85,
                source="risk-combination",
            )
        )

    if identity and credential_lure:
        add(
            "combo_brand_plus_lure",
            "Impersonation plus credential lure",
            "A lookalike brand indicator co-occurs with credential or urgency language.",
            8,
            SignalCategory.IDENTITY,
        )
    if payment and pressure:
        add(
            "combo_payment_pressure",
            "Payment request under pressure",
            "A payment instruction is combined with urgency, fear or authority pressure.",
            6,
            SignalCategory.PAYMENT,
        )
    if visual and (identity or auth):
        add(
            "combo_visual_domain_mismatch",
            "Visual identity conflicts with infrastructure",
            "The page visually claims a brand while the associated domain or identity evidence disagrees.",
            10,
            SignalCategory.VISUAL,
        )
    if auth and (payment or pressure):
        add(
            "combo_auth_payment",
            "Authentication failure on a financial request",
            "Email authentication failed on a message that requests payment or creates urgency.",
            8,
            SignalCategory.AUTH,
        )
    high_signals = [signal for signal in signals if signal.severity.rank >= Severity.HIGH.rank]
    if len(high_signals) >= 3:
        add(
            "combo_multiple_high",
            "Multiple independent high-severity indicators",
            f"{len(high_signals)} high/critical indicators from different checks agree.",
            5,
            SignalCategory.CONTENT,
        )
    return combos


def _confidence(evidence: list[Evidence], signals: list[Signal], score: int) -> tuple[float, str]:
    if not evidence:
        return 0.35, "No evidence was collected; confidence is minimal."
    verified = sum(1 for item in evidence if item.verified)
    ratio = verified / len(evidence)
    intelligence = [
        item for item in evidence if item.kind.value == "threat_intel"
    ]
    verified_intel = sum(1 for item in intelligence if item.verified)
    breadth = min(1.0, len(evidence) / 8)
    severity_weight = min(1.0, score / 70)
    raw = 0.32 + 0.3 * ratio + 0.16 * breadth + 0.12 * severity_weight + 0.1 * min(1.0, verified_intel / 3)
    basis = (
        f"{verified}/{len(evidence)} evidence items independently verified; "
        f"{len(signals)} weighted signals across "
        f"{len({signal.category for signal in signals})} categories"
        + (f"; {verified_intel} verified threat-intelligence source(s)" if verified_intel else "")
        + "."
    )
    return round(clamp(raw, 0.3, 0.97), 2), basis


class RiskEngine:
    category_caps = CATEGORY_CAPS

    def assess(
        self,
        signals: list[Signal],
        evidence: list[Evidence],
        *,
        module: str,
        summary: str | None = None,
        completeness: float | None = None,
    ) -> RiskAssessment:
        valid_ids = {item.id for item in evidence}
        merged: dict[str, Signal] = {}
        for signal in signals:
            if signal.weight <= 0:
                continue
            existing = merged.get(signal.id)
            if existing is None or signal.weight > existing.weight:
                cleaned = signal.model_copy(
                    update={
                        "evidence_ids": [item for item in signal.evidence_ids if item in valid_ids]
                    }
                )
                merged[signal.id] = cleaned

        ordered = sorted(merged.values(), key=lambda item: item.weight, reverse=True)
        category_ids: dict[SignalCategory, set[str]] = defaultdict(set)
        for signal in ordered:
            category_ids[signal.category].add(signal.id)

        combos = _combo_rules(ordered, category_ids)
        ordered.extend(combos)
        for combo in combos:
            category_ids[combo.category].add(combo.id)

        category_scores: dict[str, int] = {}
        factors: list[RiskFactor] = []
        for category in SignalCategory:
            category_signals = [signal for signal in ordered if signal.category == category]
            if not category_signals:
                continue
            total = sum(signal.weight for signal in category_signals)
            capped = min(CATEGORY_CAPS.get(category, 20), total)
            category_scores[category.value] = capped
            for signal in category_signals:
                factors.append(
                    RiskFactor(
                        id=signal.id,
                        label=signal.label,
                        category=category,
                        weight=signal.weight,
                        reason=signal.description,
                        evidence_ids=signal.evidence_ids,
                    )
                )

        score = min(100, sum(category_scores.values()))
        evidence_count = len(evidence)
        inconclusive = evidence_count == 0
        verdict = _verdict(score, inconclusive)
        confidence, basis = _confidence(evidence, ordered, score)
        if completeness is not None:
            confidence = round(clamp(confidence * (0.75 + 0.25 * completeness), 0.25, 0.97), 2)
            basis += f" Investigation completeness: {int(completeness * 100)}%."
        if inconclusive:
            confidence = min(confidence, 0.4)

        if summary is None:
            if inconclusive:
                summary = "No usable evidence was collected, so no verdict can be supported."
            elif score == 0:
                summary = "No weighted risk indicators were found in the collected evidence."
            else:
                top = factors[:4]
                summary = (
                    f"Risk score {score}/100 ({verdict.value.replace('_', ' ')}). "
                    "Principal factors: " + "; ".join(item.label for item in top) + "."
                )
        return RiskAssessment(
            score=score,
            severity=_severity(score),
            verdict=verdict,
            confidence=confidence,
            factors=sorted(factors, key=lambda item: item.weight, reverse=True)[:40],
            category_scores=category_scores,
            summary=summary,
            confidence_basis=basis,
            evidence_coverage=round(min(1.0, evidence_count / 8), 2),
        )
