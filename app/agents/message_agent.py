"""Message Investigation Agent."""

from __future__ import annotations

from typing import Any

from app.agents.base import BaseAgent
from app.agents.runtime import AgentRuntime
from app.agents.state import InvestigationState
from app.agents.types import ToolResult
from app.schemas import Finding, Severity


class MessageInvestigationAgent(BaseAgent):
    name = "message"
    display_name = "Message Investigation Agent"
    llm_tools: list[str] = []

    def plan_tools(self, state: InvestigationState, runtime: AgentRuntime) -> list[tuple[str, dict[str, Any]]]:
        payload = state.get("input") or {}
        return [
            (
                "analyze_message",
                {
                    "text": payload.get("text") or "",
                    "language": payload.get("language") or runtime.language,
                    "channel": payload.get("channel") or "sms",
                    "sender": payload.get("sender"),
                    "metadata": payload.get("metadata") or {},
                },
            )
        ]

    def deterministic_findings(
        self,
        state: InvestigationState,
        results: list[ToolResult],
        analysis: dict[str, Any] | None,
        runtime: AgentRuntime,
    ) -> list[Finding]:
        result = next((item for item in results if item.name == "analyze_message"), None)
        if result is None:
            return []
        data = result.data
        scam_types = data.get("scam_types") or []
        manipulation = data.get("manipulation") or []
        entities = data.get("entities") or {}
        signal_evidence = next(
            (item for item in result.evidence if item.kind.value == "message_signal"), None
        )
        evidence_ids = [signal_evidence.id] if signal_evidence else [item.id for item in result.evidence]
        findings: list[Finding] = []

        total_weight = min(100, sum(int(item.get("weight") or 0) for item in manipulation))
        high_tactics = {
            item.get("tactic")
            for item in manipulation
            if item.get("tactic")
            in {
                "otp_request", "remote_access", "payment_receive_lie", "secrecy",
                "authority_impersonation", "job_fee", "lottery_fee", "credential_request",
            }
        }
        top = scam_types[0] if scam_types else None
        top_confidence = float(top.get("confidence") or 0) if top else 0
        if top and (top_confidence >= 0.45 or total_weight >= 14):
            label = str(top["type"]).replace("_", " ")
            severity = (
                Severity.CRITICAL
                if high_tactics and total_weight >= 24
                else Severity.HIGH
                if total_weight >= 24 or high_tactics
                else Severity.MEDIUM
            )
            tactics_text = "; ".join(
                f"{item.get('label')}: “{item.get('quote')}”"
                for item in manipulation[:4]
            )
            entity_text = []
            if entities.get("upi_ids"):
                entity_text.append("UPI: " + ", ".join(entities["upi_ids"][:3]))
            if entities.get("amounts"):
                entity_text.append("Amounts: " + ", ".join(entities["amounts"][:3]))
            if entities.get("phone_numbers"):
                entity_text.append("Phone: " + ", ".join(entities["phone_numbers"][:3]))
            description = (
                f"Multilingual analysis classifies this message as consistent with **{label}** "
                f"(confidence {int(top_confidence * 100)}%). Language: {data.get('language')} "
                f"({data.get('script')}). Weighted tactic score: {total_weight}. "
                + (f"Supporting tactics: {tactics_text}. " if tactics_text else "")
                + (f"Extracted entities: {'; '.join(entity_text)}. " if entity_text else "")
                + "The wording alone is not proof of fraud; links and payment identifiers are "
                "investigated separately by the URL agent."
            )
            findings.append(
                self.finding(
                    f"Message consistent with {label}",
                    description,
                    severity,
                    min(0.96, max(0.55, top_confidence)),
                    evidence_ids,
                    tags=[str(item["type"]) for item in scam_types[:5]],
                    techniques=["T1566 Phishing", "T1656 Impersonation"]
                    if top["type"] in {"phishing", "otp_theft", "kyc_fraud"}
                    else [],
                )
            )

        if manipulation and (total_weight >= 10 or high_tactics):
            top_tactics = ", ".join(item.get("label", "") for item in manipulation[:5])
            severity = Severity.HIGH if high_tactics else Severity.MEDIUM
            findings.append(
                self.finding(
                    "Psychological manipulation detected",
                    f"The message uses identifiable pressure tactics: {top_tactics}. "
                    "These tactics are designed to shorten the time available for independent verification. "
                    "Quoted wording is preserved in the evidence ledger.",
                    severity,
                    0.82,
                    evidence_ids,
                    tags=["social_engineering"] + [str(item.get("tactic")) for item in manipulation[:5]],
                )
            )

        if entities.get("upi_ids") and any(
            item.get("tactic") in {"payment_request", "payment_receive_lie"} for item in manipulation
        ):
            findings.append(
                self.finding(
                    "Payment destination embedded in message",
                    "The message combines a payment instruction with a UPI address: "
                    + ", ".join(entities["upi_ids"][:4])
                    + ". A payment sent to a UPI VPA is difficult to reverse. Verify the payee "
                    "inside your own payment app, not through the message.",
                    Severity.HIGH,
                    0.86,
                    evidence_ids,
                    tags=["upi_fraud", "payment_instruction"],
                )
            )

        if data.get("protective_phrases"):
            # This is not a finding; it is captured in evidence. Kept explicit for reporters.
            pass

        return findings
