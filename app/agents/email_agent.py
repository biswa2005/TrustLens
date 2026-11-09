"""Email Forensics Investigation Agent.

Collects header, body, authentication and attachment evidence, then reasons about
Business Email Compromise, spoofing and credential-phishing patterns.  Header
``Authentication-Results`` are treated as claims; live DNS verification is
preferred and its absence is reported honestly.
"""

from __future__ import annotations

import time
from typing import Any

from app.agents.base import BaseAgent
from app.agents.runtime import AgentRuntime
from app.agents.state import InvestigationState
from app.agents.types import ToolResult
from app.engine.utils import dedupe, truncate
from app.schemas import AgentTraceEntry, Finding, Severity


def _first(value: Any) -> Any:
    """Authentication headers often carry repeated dkim results as a list."""

    if isinstance(value, list):
        return value[0] if value else None
    return value


class EmailForensicsAgent(BaseAgent):
    name = "email"
    display_name = "Email Forensics Agent"
    llm_tools: list[str] = []

    def plan_tools(
        self, state: InvestigationState, runtime: AgentRuntime
    ) -> list[tuple[str, dict[str, Any]]]:
        # ``parse_email`` must run first because ``verify_email_auth`` consumes the
        # parsed MIME object from the toolbox artifact cache.
        return [("parse_email", {}), ("verify_email_auth", {})]

    async def run(
        self, state: InvestigationState, runtime: AgentRuntime
    ) -> dict[str, Any]:
        output = await super().run(state, runtime)

        parsed = runtime.toolbox.artifacts.get("parsed_email") or {}
        body = str(parsed.get("body_text") or "").strip()
        if len(body) < 20:
            return output

        started = time.perf_counter()
        try:
            result = await runtime.toolbox.call(
                "analyze_message",
                {
                    "text": body,
                    "language": state.get("language") or runtime.language,
                    "channel": "email",
                    "sender": parsed.get("from_address"),
                    "metadata": {
                        "subject": parsed.get("subject"),
                        "from_domain": parsed.get("from_domain"),
                    },
                },
            )
        except Exception as exc:  # body analysis is valuable but not mandatory
            output.setdefault("trace", []).append(
                AgentTraceEntry(
                    agent=self.name,
                    step="body-analysis",
                    action="Email body signal analysis failed",
                    tool="analyze_message",
                    detail=truncate(f"{type(exc).__name__}: {exc}", 400),
                    status="warning",
                    latency_ms=int((time.perf_counter() - started) * 1000),
                )
            )
            return output

        extra_findings = self._body_findings(result)
        output["findings"] = list(output.get("findings") or []) + extra_findings
        output["signals"] = list(output.get("signals") or []) + result.signals
        output["iocs"] = dedupe_iocs(list(output.get("iocs") or []) + result.iocs)
        output["pending_urls"] = dedupe(
            list(output.get("pending_urls") or []) + result.pending_urls
        )
        output.setdefault("trace", []).append(
            AgentTraceEntry(
                agent=self.name,
                step="body-analysis",
                action="Ran multilingual analysis over the email body",
                tool="analyze_message",
                detail=truncate(result.summary, 400),
                status="ok",
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        )
        summaries = output.get("agent_summaries") or []
        if summaries:
            summaries[0]["summary"] = truncate(
                f"{summaries[0].get('summary', '')} Body analysis: {result.summary}", 1400
            )
        return output

    # ------------------------------------------------------------- findings
    def deterministic_findings(
        self,
        state: InvestigationState,
        results: list[ToolResult],
        analysis: dict[str, Any] | None,
        runtime: AgentRuntime,
    ) -> list[Finding]:
        parse = next((item for item in results if item.name == "parse_email"), None)
        if parse is None:
            return []
        verify = next((item for item in results if item.name == "verify_email_auth"), None)

        data = parse.data
        flags = data.get("flags") or []
        flag_map = {str(item.get("id")): item for item in flags if isinstance(item, dict)}
        headers_ids = [item.id for item in parse.evidence if item.kind.value == "email_headers"]
        body_ids = [item.id for item in parse.evidence if item.kind.value == "email_body"]
        attachment_ids = [
            item.id for item in parse.evidence if item.kind.value == "email_attachment"
        ]
        auth_claim_ids = [
            item.id for item in parse.evidence if item.kind.value == "email_auth"
        ]
        verify_ids = (
            [item.id for item in verify.evidence if item.kind.value == "email_auth"]
            if verify
            else []
        )
        auth_refs = verify_ids or auth_claim_ids or headers_ids

        findings: list[Finding] = []
        findings.extend(self._auth_findings(data, verify, auth_refs, flag_map))
        findings.extend(self._identity_findings(flag_map, headers_ids))
        findings.extend(self._bec_findings(data, flag_map, body_ids or headers_ids))
        findings.extend(self._attachment_findings(data, parse, attachment_ids))
        findings.extend(self._html_findings(flag_map, body_ids or headers_ids))
        return findings

    def _auth_findings(
        self,
        data: dict[str, Any],
        verify: ToolResult | None,
        refs: list[str],
        flag_map: dict[str, dict[str, Any]],
    ) -> list[Finding]:
        auth = (verify.data.get("auth") or {}) if verify and verify.data else {}
        live = bool(auth.get("enabled"))
        spf = (auth.get("spf") or {}).get("result")
        dkim = (auth.get("dkim") or {}).get("result")
        dmarc = (auth.get("dmarc") or {}).get("result")
        findings: list[Finding] = []

        if live:
            failures = []
            if spf in {"fail", "softfail"}:
                failures.append(f"SPF {spf}")
            if dkim == "fail":
                failures.append("DKIM fail")
            if dmarc == "fail":
                failures.append("DMARC fail")
            if failures:
                payment_or_exec = any(
                    key in flag_map
                    for key in ("payment_change_request", "executive_impersonation")
                )
                findings.append(
                    self.finding(
                        "Email authentication fails independent verification",
                        "Live checks against the sender domain's DNS policy returned: "
                        + ", ".join(failures)
                        + ". "
                        + str(auth.get("summary") or "")
                        + " This means the message's claimed sender identity is not authenticated "
                        "by the domain it appears to come from.",
                        Severity.CRITICAL if dmarc == "fail" and payment_or_exec else Severity.HIGH,
                        0.95,
                        refs,
                        tags=["email", "authentication_failure", "spoofing"],
                        techniques=["T1656 Impersonation", "T1566 Phishing"],
                    )
                )
            elif dmarc == "none":
                findings.append(
                    self.finding(
                        "Sender domain publishes no DMARC policy",
                        "SPF/DKIM were evaluated but the From domain has no DMARC record, so receivers "
                        "cannot enforce alignment. This is a weakness of the sending domain, not proof "
                        "that this specific message is fraudulent.",
                        Severity.LOW,
                        0.85,
                        refs,
                        tags=["email", "no_dmarc"],
                    )
                )

            # Header claims that contradict independent verification are especially serious.
            header_spf = _first((data.get("auth_results") or {}).get("spf"))
            header_dmarc = _first((data.get("auth_results") or {}).get("dmarc"))
            if header_spf == "pass" and spf in {"fail", "softfail"}:
                findings.append(
                    self.finding(
                        "Authentication-Results header conflicts with live SPF",
                        "The message header claims SPF pass, but independent evaluation returned "
                        f"'{spf}'. Authentication headers can be added or forged by intermediaries; "
                        "the live result is treated as authoritative.",
                        Severity.CRITICAL,
                        0.92,
                        refs,
                        tags=["email", "header_conflict", "spoofing"],
                    )
                )
            if header_dmarc == "pass" and dmarc == "fail":
                findings.append(
                    self.finding(
                        "Authentication-Results header conflicts with live DMARC",
                        "The message header claims DMARC pass, but independent alignment failed. "
                        "This is a strong indicator that the recorded authentication result is not "
                        "trustworthy for this message.",
                        Severity.CRITICAL,
                        0.94,
                        refs,
                        tags=["email", "header_conflict", "spoofing"],
                    )
                )
            return findings

        # Network disabled or verification unavailable: report only the recorded claims.
        claims = data.get("auth_results") or {}
        claimed_failures = []
        for name in ("spf", "dkim", "dmarc"):
            value = _first(claims.get(name))
            if value in {"fail", "softfail"}:
                claimed_failures.append(f"{name.upper()} {value}")
        if claimed_failures:
            findings.append(
                self.finding(
                    "Recorded authentication headers report failure",
                    "The message's own Authentication-Results header reports: "
                    + ", ".join(claimed_failures)
                    + ". These values are unverified claims, not independent observations, but a "
                    "recorded failure is still a meaningful warning.",
                    Severity.HIGH,
                    0.68,
                    refs,
                    tags=["email", "authentication_claim", "unverified"],
                )
            )
        elif claims:
            findings.append(
                self.finding(
                    "Email authentication was not independently verified",
                    "The message contains authentication claims, but live SPF/DKIM/DMARC verification "
                    "was unavailable (network disabled or no originating IP). No conclusion about "
                    "sender authenticity can be drawn from the header claims alone.",
                    Severity.INFO,
                    0.5,
                    refs,
                    tags=["email", "authentication_unverified"],
                )
            )
        return findings

    def _identity_findings(
        self, flag_map: dict[str, dict[str, Any]], refs: list[str]
    ) -> list[Finding]:
        identity_ids = {
            "reply_to_mismatch",
            "return_path_mismatch",
            "sender_header_mismatch",
            "display_name_embeds_other_address",
            "display_brand_not_official_domain",
            "punycode_sender",
            "free_mail_brand_claim",
            "message_id_domain_mismatch",
        }
        selected = [flag_map[key] for key in identity_ids if key in flag_map]
        if not selected:
            return []
        details = "; ".join(
            f"{item.get('label')}: {item.get('detail')}" for item in selected[:6]
        )
        severe = any(
            item.get("id") in {
                "display_brand_not_official_domain",
                "punycode_sender",
                "display_name_embeds_other_address",
            }
            for item in selected
        )
        return [
            self.finding(
                "Sender identity inconsistencies",
                "Header analysis found identity mismatches: "
                + details
                + ". These do not by themselves prove fraud, but legitimate senders normally keep "
                "From, Reply-To, Return-Path and Message-ID aligned with their own domain.",
                Severity.HIGH if severe else Severity.MEDIUM,
                0.86,
                refs,
                tags=["email", "identity_mismatch"] + [str(item.get("id")) for item in selected[:6]],
                techniques=["T1656 Impersonation"] if severe else [],
            )
        ]

    def _bec_findings(
        self,
        data: dict[str, Any],
        flag_map: dict[str, dict[str, Any]],
        refs: list[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        bec_ids = {"payment_change_request", "executive_impersonation", "fake_thread"}
        selected = [flag_map[key] for key in bec_ids if key in flag_map]
        if "payment_change_request" in flag_map or "executive_impersonation" in flag_map:
            combined = "payment_change_request" in flag_map and (
                "executive_impersonation" in flag_map
                or any(
                    key in flag_map
                    for key in ("reply_to_mismatch", "display_brand_not_official_domain")
                )
            )
            findings.append(
                self.finding(
                    "Business Email Compromise pattern",
                    "The email combines "
                    + "; ".join(
                        f"{item.get('label')}: {item.get('detail')}" for item in selected
                    )
                    + ". BEC messages typically request a payment or bank-detail change while "
                    "impersonating an executive or supplier. No payment should be made until the "
                    "request is verified through a previously known phone number or in person.",
                    Severity.CRITICAL if combined else Severity.HIGH,
                    0.9 if combined else 0.82,
                    refs,
                    tags=["email", "bec", "payment_fraud"],
                    techniques=["T1656 Impersonation", "T1657 Financial Theft"],
                )
            )
        invoice = flag_map.get("invoice_attachment")
        if invoice:
            findings.append(
                self.finding(
                    "Invoice-themed attachment",
                    "The message carries an invoice/payment-themed attachment: "
                    + str(invoice.get("detail") or "")
                    + " Invoice attachments are frequently used to deliver malware or to support a "
                    "fraudulent payment change. Confirm the invoice through an independent channel.",
                    Severity.MEDIUM,
                    0.8,
                    refs,
                    tags=["email", "invoice", "attachment"],
                )
            )
        return findings

    def _attachment_findings(
        self, data: dict[str, Any], parse: ToolResult, refs: list[str]
    ) -> list[Finding]:
        attachments = data.get("attachments") or []
        evidence_ids = [item.id for item in parse.evidence if item.kind.value == "email_attachment"]
        findings: list[Finding] = []
        severe_flags = {
            "executable_extension",
            "content_type_mismatch_executable",
            "contains_executable",
            "macro_enabled_document",
            "contains_macros",
            "auto_exec_macro",
            "dde_execution",
            "pdf_active_content",
            "attachment_credential_form",
            "double_extension",
            "contains_vba",
        }
        for index, attachment in enumerate(attachments):
            if not isinstance(attachment, dict):
                continue
            flags = [str(item) for item in (attachment.get("flags") or [])]
            if not flags:
                continue
            name = str(attachment.get("filename") or f"attachment-{index}")
            ref = evidence_ids[index] if index < len(evidence_ids) else (refs[0] if refs else "")
            severe = bool(set(flags) & severe_flags)
            findings.append(
                self.finding(
                    f"Risky attachment: {name}",
                    f"Static triage of '{name}' ({attachment.get('content_type')}, "
                    f"{attachment.get('size')} bytes) found: {', '.join(flags)}. "
                    "The attachment was not executed and archives were not extracted. "
                    + (
                        "Executable, macro or active-content indicators mean this file should be "
                        "detonated only in an isolated sandbox by a trained analyst."
                        if severe
                        else "Treat the file as untrusted until it is verified through the sender's "
                        "official channel."
                    ),
                    Severity.HIGH if severe else Severity.MEDIUM,
                    0.9 if severe else 0.78,
                    [ref] if ref else refs,
                    tags=["email", "attachment", "malware_risk"]
                    + (["active_content"] if severe else []),
                    techniques=["T1204 User Execution"] if severe else [],
                )
            )
        return findings

    def _html_findings(
        self, flag_map: dict[str, dict[str, Any]], refs: list[str]
    ) -> list[Finding]:
        credential = flag_map.get("html_password_form") or flag_map.get("html_external_form")
        findings: list[Finding] = []
        if credential:
            findings.append(
                self.finding(
                    "Credential-harvesting form inside the email",
                    str(credential.get("detail") or "")
                    + " A password form delivered inside an email is a strong phishing indicator; "
                    "legitimate senders do not collect credentials this way.",
                    Severity.HIGH,
                    0.88,
                    refs,
                    tags=["email", "credential_harvest", "phishing"],
                    techniques=["T1566 Phishing"],
                )
            )
        mismatch = flag_map.get("html_link_text_mismatch")
        hidden = flag_map.get("html_hidden_text")
        if mismatch or hidden:
            details = "; ".join(
                str(item.get("detail"))
                for item in (mismatch, hidden)
                if isinstance(item, dict)
            )
            findings.append(
                self.finding(
                    "Deceptive HTML construction in the email",
                    details
                    + " Link text or hidden content is designed to make the message look safer than "
                    "the underlying destinations. The queued URLs are investigated separately.",
                    Severity.MEDIUM,
                    0.82,
                    refs,
                    tags=["email", "html_obfuscation", "phishing"],
                )
            )
        return findings

    def _body_findings(self, result: ToolResult) -> list[Finding]:
        data = result.data
        scam_types = data.get("scam_types") or []
        manipulation = data.get("manipulation") or []
        signal_ids = [
            item.id for item in result.evidence if item.kind.value == "message_signal"
        ]
        refs = signal_ids or [item.id for item in result.evidence]
        if not refs:
            return []
        findings: list[Finding] = []
        total_weight = min(100, sum(int(item.get("weight") or 0) for item in manipulation))
        top = scam_types[0] if scam_types else None
        top_confidence = float(top.get("confidence") or 0) if top else 0
        if top and (top_confidence >= 0.45 or total_weight >= 14):
            label = str(top.get("type") or "").replace("_", " ")
            findings.append(
                self.finding(
                    f"Email content consistent with {label}",
                    "Multilingual analysis of the email body classifies it as consistent with "
                    f"**{label}** (confidence {int(top_confidence * 100)}%). "
                    + (
                        "Supporting tactics: "
                        + "; ".join(
                            f"{item.get('label')}: “{item.get('quote')}”"
                            for item in manipulation[:4]
                        )
                        + ". "
                        if manipulation
                        else ""
                    )
                    + "The wording alone is not proof; sender authentication, links and attachments "
                    "are assessed separately.",
                    Severity.HIGH
                    if any(
                        item.get("tactic")
                        in {
                            "otp_request", "remote_access", "payment_receive_lie",
                            "credential_request", "authority_impersonation",
                        }
                        for item in manipulation
                    )
                    else Severity.MEDIUM,
                    min(0.94, max(0.55, top_confidence)),
                    refs,
                    tags=["email", "body_analysis", str(top.get("type"))],
                    techniques=["T1566 Phishing"],
                )
            )
        if manipulation and (total_weight >= 10 or len(manipulation) >= 2):
            findings.append(
                self.finding(
                    "Manipulation tactics in email body",
                    "The body uses pressure or persuasion tactics: "
                    + ", ".join(str(item.get("label")) for item in manipulation[:6])
                    + ". Quoted wording is preserved in the evidence ledger.",
                    Severity.MEDIUM,
                    0.78,
                    refs,
                    tags=["email", "social_engineering"],
                )
            )
        return findings


def dedupe_iocs(items: list[Any]) -> list[Any]:
    """Keep the highest-risk observation for each IOC value."""

    best: dict[tuple[str, str], Any] = {}
    for item in items:
        key = (getattr(item, "type", ""), getattr(item, "value", ""))
        existing = best.get(key)
        if existing is None:
            best[key] = item
            continue
        current_rank = getattr(getattr(item, "risk", None), "rank", 0)
        existing_rank = getattr(getattr(existing, "risk", None), "rank", 0)
        if current_rank > existing_rank:
            best[key] = item
    return list(best.values())
