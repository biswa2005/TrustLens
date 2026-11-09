"""QR Investigation Agent."""

from __future__ import annotations

from typing import Any

from app.agents.base import BaseAgent
from app.agents.runtime import AgentRuntime
from app.agents.state import InvestigationState
from app.agents.types import ToolResult
from app.schemas import Finding, Severity


class QRInvestigationAgent(BaseAgent):
    name = "qr"
    display_name = "QR Investigation Agent"
    llm_tools: list[str] = []

    def plan_tools(self, state: InvestigationState, runtime: AgentRuntime) -> list[tuple[str, dict[str, Any]]]:
        tools: list[tuple[str, dict[str, Any]]] = [("decode_qr", {})]
        if runtime.llm.available and state.get("artifacts", {}).get("image_bytes"):
            tools.append(("analyze_qr_context", {}))
        return tools

    def deterministic_findings(
        self,
        state: InvestigationState,
        results: list[ToolResult],
        analysis: dict[str, Any] | None,
        runtime: AgentRuntime,
    ) -> list[Finding]:
        decode = next((item for item in results if item.name == "decode_qr"), None)
        if decode is None or not (decode.data.get("decode") or {}).get("decoded"):
            return []
        inspections = decode.data.get("inspections") or []
        findings: list[Finding] = []
        upi_evidence = [item.id for item in decode.evidence if item.kind.value == "upi_uri"]
        payload_evidence = [item.id for item in decode.evidence if item.kind.value == "qr_payload"]
        image_evidence = [item.id for item in decode.evidence if item.kind.value == "qr_image"]
        refs = upi_evidence or payload_evidence or image_evidence

        for info in inspections:
            if info.get("kind") == "upi_payment":
                upi = info.get("upi") or {}
                warnings = info.get("warnings") or []
                severe = any(
                    word in warning.lower()
                    for warning in warnings
                    for word in ("receive", "refund", "cashback", "debit", "not one of its known")
                )
                description = (
                    "The QR encodes a UPI payment URI"
                    + (f" to **{upi.get('payee_name') or 'an unnamed payee'}**" if upi.get("payee_name") else "")
                    + (f" (`{upi.get('payee_vpa')}`)" if upi.get("payee_vpa") else "")
                    + (f" for **{upi.get('amount')} {upi.get('currency') or 'INR'}**" if upi.get("amount") else "")
                    + ". Approving this QR/collect request **debits the scanner's account**; it cannot "
                    "deliver a refund, prize or incoming payment. "
                    + ("Warnings: " + "; ".join(warnings[:5]) + "." if warnings else "")
                )
                findings.append(
                    self.finding(
                        "UPI payment QR code",
                        description,
                        Severity.CRITICAL if severe else Severity.HIGH,
                        0.94,
                        refs,
                        tags=["qr", "upi_fraud", "payment_request"],
                        techniques=["T1657 Financial Theft"],
                    )
                )
                if warnings:
                    findings.append(
                        self.finding(
                            "QR payment warnings",
                            "The decoded UPI URI raised these specific concerns: "
                            + "; ".join(warnings[:6]),
                            Severity.CRITICAL if severe else Severity.MEDIUM,
                            0.88,
                            upi_evidence or refs,
                            tags=["qr", "payment_warning"],
                        )
                    )
            elif info.get("kind") in {"url", "text_with_url"}:
                urls = info.get("urls") or []
                findings.append(
                    self.finding(
                        "QR code directs to an external URL",
                        "The QR decodes to: " + ", ".join(urls[:3]) + ". The destination has been queued "
                        "for URL and domain intelligence; the QR image alone cannot establish safety.",
                        Severity.MEDIUM,
                        0.8,
                        payload_evidence or refs,
                        tags=["qr", "external_url"],
                    )
                )
            elif info.get("kind") == "wifi":
                wifi = info.get("wifi") or {}
                findings.append(
                    self.finding(
                        "Wi-Fi joining QR",
                        f"The QR configures a Wi-Fi connection to SSID '{wifi.get('ssid')}' with "
                        f"security '{wifi.get('security')}'. "
                        + (
                            "An open network allows traffic interception; avoid sensitive logins."
                            if wifi.get("risk") == "open"
                            else "Verify the SSID with staff before joining."
                        ),
                        Severity.HIGH if wifi.get("risk") == "open" else Severity.LOW,
                        0.82,
                        image_evidence or refs,
                        tags=["qr", "wifi"],
                    )
                )
            elif info.get("kind") == "crypto_payment":
                crypto = info.get("crypto") or {}
                findings.append(
                    self.finding(
                        "Cryptocurrency payment QR",
                        f"The QR requests an irreversible {crypto.get('asset')} transfer to "
                        f"`{crypto.get('address')}`. Crypto transfers have no chargeback. Verify the "
                        "recipient through an independent channel.",
                        Severity.HIGH,
                        0.9,
                        payload_evidence or refs,
                        tags=["qr", "crypto"],
                    )
                )

        context_result = next((item for item in results if item.name == "analyze_qr_context"), None)
        if context_result and context_result.signals:
            findings.append(
                self.finding(
                    "QR context contains a deceptive claim",
                    context_result.summary
                    + " A UPI payment QR can only debit the person scanning it; claims that it delivers "
                    "money, a refund or a prize are inconsistent with how UPI works.",
                    Severity.CRITICAL,
                    0.78,
                    [item.id for item in context_result.evidence],
                    tags=["qr", "social_engineering"],
                )
            )
        return findings
