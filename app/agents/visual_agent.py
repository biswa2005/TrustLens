"""Visual Website Investigation Agent.

The agent combines a vision-language observation of the uploaded screenshot with
deterministic brand-registry checks.  Visual similarity is never treated as proof
that a site belongs to a brand; domain ownership is established separately by the
URL Intelligence Agent.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from app.agents.base import BaseAgent
from app.agents.runtime import AgentRuntime
from app.agents.state import InvestigationState
from app.agents.types import ToolResult
from app.engine.urls import registrable_domain
from app.schemas import Finding, Severity


def _host_from_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    try:
        return (urlsplit(value).hostname or "").lower().strip(".")
    except ValueError:
        return ""


class VisualWebsiteAgent(BaseAgent):
    name = "visual"
    display_name = "Visual Website Investigation Agent"
    # local_ocr is deliberately not planned: the screenshot tool already falls back
    # to Tesseract when the vision model is unavailable.
    llm_tools: list[str] = []

    def plan_tools(
        self, state: InvestigationState, runtime: AgentRuntime
    ) -> list[tuple[str, dict[str, Any]]]:
        artifacts = state.get("artifacts") or {}
        payload = state.get("input") or {}
        brand_hint = str(
            artifacts.get("brand_hint")
            or payload.get("brand_hint")
            or ""
        ).strip()
        claimed_url = str(
            artifacts.get("claimed_url")
            or payload.get("claimed_url")
            or ""
        ).strip()
        tools: list[tuple[str, dict[str, Any]]] = [
            (
                "analyze_screenshot",
                {"brand_hint": brand_hint, "claimed_url": claimed_url},
            )
        ]
        brand = runtime.services.brands.get(brand_hint) if brand_hint else None
        if brand is not None:
            tools.append(
                ("compare_brand_reference", {"brand_slug": str(brand.get("slug") or "")})
            )
        return tools

    def deterministic_findings(
        self,
        state: InvestigationState,
        results: list[ToolResult],
        analysis: dict[str, Any] | None,
        runtime: AgentRuntime,
    ) -> list[Finding]:
        screenshot = next((item for item in results if item.name == "analyze_screenshot"), None)
        if screenshot is None:
            return []

        vision = (screenshot.data.get("vision") or {}) if isinstance(screenshot.data, dict) else {}
        brand_hint = str(screenshot.data.get("brand_hint") or "")
        claimed_url = str(screenshot.data.get("claimed_url") or "")
        image_ids = [item.id for item in screenshot.evidence if item.kind.value == "image"]
        vlm_ids = [item.id for item in screenshot.evidence if item.kind.value == "vlm_observation"]
        ocr_ids = [item.id for item in screenshot.evidence if item.kind.value == "ocr_text"]
        base_refs = vlm_ids or ocr_ids or image_ids

        findings: list[Finding] = []
        if not vision:
            local_ocr = (screenshot.data.get("local_ocr") or {}) if isinstance(screenshot.data, dict) else {}
            if local_ocr.get("available") and local_ocr.get("text"):
                findings.append(
                    self.finding(
                        "Screenshot could only be inspected with local OCR",
                        "The vision model was unavailable, so the page was not visually compared with "
                        "the claimed brand. OCR text was captured as evidence, but no impersonation "
                        "judgement can be supported from OCR alone. Treat the visual verdict as "
                        "incomplete and verify the site through its official app or domain.",
                        Severity.INFO,
                        0.45,
                        ocr_ids or image_ids,
                        tags=["visual", "incomplete_analysis"],
                    )
                )
            else:
                findings.append(
                    self.finding(
                        "Screenshot could not be visually analysed",
                        "No vision-language model or local OCR result was available, so the screenshot "
                        "was only stored as an image. The page's brand, address bar and form fields were "
                        "not assessed. No conclusion about legitimacy or impersonation can be drawn; "
                        "configure a Hugging Face vision model or enable Tesseract OCR.",
                        Severity.INFO,
                        0.35,
                        image_ids,
                        tags=["visual", "analysis_unavailable"],
                    )
                )
            return findings

        brand_guess = str(vision.get("brand_guess") or brand_hint or "").strip()
        claims_brand = bool(vision.get("claims_brand"))
        confidence = float(vision.get("impersonation_confidence") or 0)
        observed_url = str(vision.get("observed_url") or "").strip()
        observed_host = _host_from_url(observed_url)
        domain_for_brand = _host_from_url(claimed_url) or observed_host
        brand = runtime.services.brands.get(brand_guess) if brand_guess else None

        if claims_brand and confidence >= 0.55:
            findings.append(
                self.finding(
                    f"Page imitates {brand_guess or 'a well-known brand'}",
                    "The vision-language analysis found that the screenshot claims the visual identity "
                    f"of **{brand_guess or 'a recognised brand'}** with "
                    f"{int(confidence * 100)}% confidence. "
                    + (
                        "Visible inconsistencies: "
                        + "; ".join(str(item) for item in (vision.get("inconsistencies") or [])[:5])
                        + ". "
                        if vision.get("inconsistencies")
                        else ""
                    )
                    + "Visual similarity alone does not prove the site is operated by that brand; "
                    "domain and certificate ownership must be checked independently.",
                    Severity.CRITICAL if confidence >= 0.8 else Severity.HIGH,
                    min(0.95, max(0.55, confidence)),
                    base_refs,
                    tags=["visual", "brand_impersonation", "phishing"],
                    techniques=["T1656 Impersonation", "T1566 Phishing"],
                )
            )

        login_form = vision.get("login_form") or {}
        if login_form.get("present"):
            fields = [str(item) for item in (login_form.get("fields") or [])][:10]
            suspicious = bool(login_form.get("suspicious"))
            findings.append(
                self.finding(
                    "Credential-collection form on the page",
                    "The screenshot shows a login/credential form"
                    + (f" with fields: {', '.join(fields)}" if fields else "")
                    + (
                        ". The vision model flagged the form as suspicious, and any credentials entered "
                        "would be disclosed to the page operator."
                        if suspicious
                        else ". Verify the domain in the address bar before entering any credential; "
                        "a password field alone is not proof of phishing."
                    ),
                    Severity.HIGH if suspicious else Severity.MEDIUM,
                    0.84 if suspicious else 0.66,
                    base_refs,
                    tags=["visual", "credential_form"]
                    + (["credential_harvest"] if suspicious else []),
                    techniques=["T1056 Input Capture"] if suspicious else [],
                )
            )

        if brand is not None and domain_for_brand:
            if not runtime.services.brands.is_official(domain_for_brand, brand):
                findings.append(
                    self.finding(
                        "Visual brand does not match the domain",
                        f"The page presents itself as **{brand.get('name') or brand_guess}**, but the "
                        f"address shown/supplied is `{domain_for_brand}`, which is not one of that "
                        "brand's registered domains: "
                        + ", ".join(brand.get("domains", [])[:5])
                        + ". This is the central impersonation signal: the visual layer claims a brand "
                        "while the infrastructure does not belong to it.",
                        Severity.CRITICAL,
                        0.9,
                        base_refs,
                        tags=["visual", "domain_mismatch", "brand_impersonation"],
                        techniques=["T1656 Impersonation"],
                    )
                )

        inconsistencies = [str(item) for item in (vision.get("inconsistencies") or []) if str(item).strip()]
        if inconsistencies:
            findings.append(
                self.finding(
                    "Visual inconsistencies in the page",
                    "The vision model observed details that do not match the claimed brand: "
                    + "; ".join(inconsistencies[:6])
                    + ". These are supporting observations, not standalone proof of fraud.",
                    Severity.MEDIUM,
                    0.72,
                    base_refs,
                    tags=["visual", "inconsistency"],
                )
            )

        phishing_cues = [
            str(item) for item in (vision.get("phishing_indicators") or []) if str(item).strip()
        ]
        if phishing_cues:
            findings.append(
                self.finding(
                    "Visual phishing cues",
                    "The screenshot contains cues commonly used in credential phishing: "
                    + "; ".join(phishing_cues[:6])
                    + ". The cues are recorded with the screenshot so a human reviewer can confirm them.",
                    Severity.HIGH,
                    0.76,
                    base_refs,
                    tags=["visual", "phishing_cue"],
                    techniques=["T1566 Phishing"],
                )
            )

        comparison = next(
            (item for item in results if item.name == "compare_brand_reference"), None
        )
        if comparison:
            info = (comparison.data.get("comparison") or {}) if isinstance(comparison.data, dict) else {}
            similarity = info.get("similarity")
            if info.get("available") and isinstance(similarity, (int, float)) and similarity >= 0.8:
                refs = [item.id for item in comparison.evidence] or base_refs
                findings.append(
                    self.finding(
                        "Perceptual match with a brand reference image",
                        f"The screenshot has a perceptual similarity of {similarity:.2f} to the local "
                        f"reference image for {brand_guess or brand_hint or 'the brand'}. This strengthens "
                        "the visual-impersonation hypothesis but does not establish who owns the domain.",
                        Severity.MEDIUM,
                        min(0.85, float(similarity)),
                        refs,
                        tags=["visual", "image_similarity"],
                    )
                )

        # If the page shows a URL that was not queued by the tool, make sure the URL
        # agent receives it.  The specialist's pending lists are merged by BaseAgent.
        if observed_url.startswith(("http://", "https://")) and not screenshot.pending_urls:
            screenshot.pending_urls.append(observed_url)
        if claimed_url.startswith(("http://", "https://")) and claimed_url not in screenshot.pending_urls:
            screenshot.pending_urls.append(claimed_url)

        # Keep a compact, report-friendly note of the observed host.
        if observed_host and not registrable_domain(observed_host):
            findings.append(
                self.finding(
                    "Address bar text could not be interpreted as a normal domain",
                    f"The vision model transcribed the address as `{observed_url}` but it does not "
                    "contain a recognisable registrable domain. Address-bar obfuscation is itself a "
                    "reason for caution.",
                    Severity.MEDIUM,
                    0.6,
                    base_refs,
                    tags=["visual", "address_bar"],
                )
            )

        return findings
