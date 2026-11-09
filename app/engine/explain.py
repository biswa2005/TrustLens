"""AI explanation and recommendation generation, grounded in the evidence ledger."""

from __future__ import annotations

import logging
from typing import Any

from app.engine.hf import LLMUnavailable
from app.engine.llm import LLMService
from app.engine.utils import language_name, truncate
from app.schemas import (
    Recommendation,
    RecommendationCategory,
    RecommendationPriority,
    RiskAssessment,
    Verdict,
)

logger = logging.getLogger(__name__)

_LANG = {
    "en": {
        "do_not_engage": ("Stop interacting with the sender", "Do not reply, call back on the supplied number, or send more money or documents."),
        "no_link": ("Do not open the link", "Type the organisation's official address yourself or use its official app instead of the supplied link."),
        "upi": ("Do not approve any UPI request", "A UPI collect request or payment QR debits your account. It never delivers a refund or prize."),
        "otp": ("Protect your OTP and credentials", "Never share an OTP, UPI PIN, card CVV or password. If you already did, call your bank's official number and change your credentials."),
        "bank": ("Contact your bank through an official channel", "Use the number printed on your card or the bank's app. Report the attempted fraud and ask for a transaction freeze if money moved."),
        "email": ("Verify payment changes out-of-band", "Confirm any bank-detail or invoice change using a known phone number, not by replying to the email."),
        "attachment": ("Do not open the attachment", "Do not enable macros or open archives. Ask IT security to inspect the file hash in a sandbox."),
        "report": ("Report the incident", "In India, report at cybercrime.gov.in or call 1930. You can also report to CERT-In and the impersonated brand."),
        "credentials_site": ("Leave the site without entering data", "Close the page and reach the brand through its official app or by typing its domain. If credentials were entered, reset them now."),
        "monitor": ("Monitor your accounts", "Review recent transactions and login alerts. Enable two-factor authentication and unique passwords."),
        "benign": ("No action required", "The available evidence does not support a fraud verdict. Stay cautious with unexpected messages and verify independently."),
    },
    "hi": {
        "do_not_engage": ("प्रेषक से आगे संपर्क बंद करें", "जवाब न दें, दिए गए नंबर पर कॉल न करें और और पैसे या दस्तावेज़ न भेजें।"),
        "no_link": ("लिंक न खोलें", "दिए गए लिंक के बजाय संस्था का आधिकारिक पता स्वयं टाइप करें या उसका आधिकारिक ऐप इस्तेमाल करें।"),
        "upi": ("किसी भी UPI अनुरोध को स्वीकार न करें", "UPI कलेक्ट अनुरोध या पेमेंट QR आपके खाते से पैसे काटता है; यह रिफंड या इनाम नहीं देता।"),
        "otp": ("OTP और गोपनीय जानकारी सुरक्षित रखें", "OTP, UPI पिन, CVV या पासवर्ड कभी साझा न करें। यदि साझा कर दिया है तो बैंक के आधिकारिक नंबर पर कॉल करें और पासवर्ड बदलें।"),
        "bank": ("बैंक से आधिकारिक माध्यम से संपर्क करें", "कार्ड पर छपे नंबर या बैंक ऐप का उपयोग करें। धोखाधड़ी की रिपोर्ट करें और पैसे कटे हों तो लेन-देन रोकने का अनुरोध करें।"),
        "email": ("भुगतान परिवर्तन की पुष्टि अलग माध्यम से करें", "ईमेल का जवाब देकर नहीं, बल्कि ज्ञात फोन नंबर पर बात करके बैंक विवरण या इनवॉइस में बदलाव की पुष्टि करें।"),
        "attachment": ("अटैचमेंट न खोलें", "मैक्रो चालू न करें और आर्काइव न खोलें। IT सुरक्षा टीम से फ़ाइल हैश की जाँच कराएँ।"),
        "report": ("घटना की रिपोर्ट करें", "भारत में cybercrime.gov.in पर या 1930 पर रिपोर्ट करें। CERT-In और जिस ब्रांड का नकल हुआ है, उसे भी सूचित करें।"),
        "credentials_site": ("बिना जानकारी दर्ज किए साइट छोड़ें", "पेज बंद करें और ब्रांड के आधिकारिक ऐप या डोमेन से जाएँ। जानकारी दर्ज कर दी है तो तुरंत पासवर्ड बदलें।"),
        "monitor": ("अपने खातों पर नज़र रखें", "हाल के लेन-देन और लॉगिन अलर्ट देखें। दो-चरणीय सुरक्षा और अलग पासवर्ड इस्तेमाल करें।"),
        "benign": ("कोई कार्रवाई आवश्यक नहीं", "उपलब्ध साक्ष्य धोखाधड़ी की पुष्टि नहीं करते। अप्रत्याशित संदेशों में सतर्क रहें और स्वतंत्र रूप से पुष्टि करें।"),
    },
    "bn": {
        "do_not_engage": ("প্রেরকের সঙ্গে যোগাযোগ বন্ধ করুন", "উত্তর দেবেন না, দেওয়া নম্বরে ফোন করবেন না এবং আর টাকা বা নথি পাঠাবেন না।"),
        "no_link": ("লিংক খুলবেন না", "প্রদত্ত লিংকের বদলে প্রতিষ্ঠানের অফিসিয়াল ঠিকানা নিজে টাইপ করুন বা অফিসিয়াল অ্যাপ ব্যবহার করুন।"),
        "upi": ("কোনো UPI অনুরোধ অনুমোদন করবেন না", "UPI collect অনুরোধ বা পেমেন্ট QR আপনার অ্যাকাউন্ট থেকে টাকা কাটে; এটি রিফান্ড বা পুরস্কার দেয় না।"),
        "otp": ("OTP ও গোপন তথ্য সুরক্ষিত রাখুন", "OTP, UPI পিন, CVV বা পাসওয়ার্ড কখনো শেয়ার করবেন না। শেয়ার করে থাকলে ব্যাংকের অফিসিয়াল নম্বরে ফোন করুন এবং পাসওয়ার্ড বদলান।"),
        "bank": ("অফিসিয়াল মাধ্যমে ব্যাংকের সঙ্গে যোগাযোগ করুন", "কার্ডে লেখা নম্বর বা ব্যাংকের অ্যাপ ব্যবহার করুন। প্রতারণার রিপোর্ট করুন এবং টাকা গেলে লেনদেন বন্ধের অনুরোধ করুন।"),
        "email": ("পেমেন্ট পরিবর্তন আলাদা মাধ্যমে যাচাই করুন", "ইমেইলের উত্তর দিয়ে নয়, পরিচিত ফোন নম্বরে কথা বলে ব্যাংক তথ্য বা ইনভয়েস পরিবর্তন যাচাই করুন।"),
        "attachment": ("সংযুক্তি খুলবেন না", "ম্যাক্রো চালু করবেন না এবং আর্কাইভ খুলবেন না। IT নিরাপত্তা দলকে ফাইলের হ্যাশ পরীক্ষা করতে বলুন।"),
        "report": ("ঘটনাটি রিপোর্ট করুন", "ভারতে cybercrime.gov.in-এ বা 1930-এ রিপোর্ট করুন। CERT-In এবং যে ব্র্যান্ডের নকল হয়েছে তাকেও জানান।"),
        "credentials_site": ("তথ্য না দিয়ে সাইট ছেড়ে যান", "পেজ বন্ধ করুন এবং ব্র্যান্ডের অফিসিয়াল অ্যাপ বা ডোমেইনে যান। তথ্য দিয়ে থাকলে এখনই পাসওয়ার্ড বদলান।"),
        "monitor": ("আপনার অ্যাকাউন্ট পর্যবেক্ষণ করুন", "সাম্প্রতিক লেনদেন ও লগইন সতর্কতা দেখুন। দুই-ধাপ যাচাই এবং আলাদা পাসওয়ার্ড ব্যবহার করুন।"),
        "benign": ("কোনো ব্যবস্থা প্রয়োজন নেই", "উপলব্ধ প্রমাণ প্রতারণা নিশ্চিত করে না। অপ্রত্যাশিত বার্তায় সতর্ক থাকুন এবং স্বাধীনভাবে যাচাই করুন।"),
    },
    "hinglish": {
        "do_not_engage": ("Sender se contact band karein", "Reply na karein, diye gaye number par call na karein, aur aur paise ya documents na bhejein."),
        "no_link": ("Link open na karein", "Diye gaye link ki jagah official website khud type karein ya official app use karein."),
        "upi": ("Koi bhi UPI request approve na karein", "UPI collect request ya payment QR aapke account se paise kaatta hai; refund ya prize nahi deta."),
        "otp": ("OTP aur credentials safe rakhein", "OTP, UPI PIN, CVV ya password kabhi share na karein. Share kar diya ho to bank ke official number par call karein aur password badlein."),
        "bank": ("Bank se official channel par contact karein", "Card par likha number ya bank app use karein. Fraud report karein aur paise kate hon to transaction freeze karwayein."),
        "email": ("Payment change ko alag channel se verify karein", "Email ka reply kiye bina, known phone number par baat karke bank details ya invoice change confirm karein."),
        "attachment": ("Attachment open na karein", "Macros enable na karein aur archive na kholein. IT security se file hash check karwayein."),
        "report": ("Incident report karein", "India mein cybercrime.gov.in par ya 1930 par report karein. CERT-In aur impersonated brand ko bhi inform karein."),
        "credentials_site": ("Bina data daale site chhod dein", "Page band karein aur brand ke official app/domain se jayein. Credentials daal diye hon to turant password reset karein."),
        "monitor": ("Apne accounts monitor karein", "Recent transactions aur login alerts check karein. Two-factor authentication aur unique password use karein."),
        "benign": ("Koi action zaroori nahi", "Available evidence fraud ko support nahi karta. Unexpected messages mein cautious rahein aur independently verify karein."),
    },
}


def _language_key(language: str) -> str:
    language = (language or "en").lower()
    return language if language in _LANG else "en"


def _details_in_english(context: dict[str, Any]) -> str:
    parts = []
    if context.get("scam_types"):
        parts.append("Signals are consistent with: " + ", ".join(item.replace("_", " ") for item in context["scam_types"][:4]) + ".")
    if context.get("urls"):
        parts.append("Investigated URL(s): " + ", ".join(context["urls"][:3]) + ".")
    if context.get("brand"):
        parts.append("Brand referenced: " + str(context["brand"]) + ".")
    if context.get("auth_summary"):
        parts.append("Email authentication: " + str(context["auth_summary"]))
    return " ".join(parts)


def build_recommendations(
    context: dict[str, Any],
    risk: RiskAssessment,
    language: str = "en",
    limit: int = 6,
) -> list[Recommendation]:
    lang = _LANG[_language_key(language)]
    tags = set(context.get("tags") or [])
    verdict = risk.verdict
    recs: list[Recommendation] = []
    immediate = verdict in {Verdict.MALICIOUS, Verdict.LIKELY_MALICIOUS}

    def add(key: str, priority: RecommendationPriority, category: RecommendationCategory) -> None:
        title, detail = lang[key]
        if any(item.title == title for item in recs):
            return
        recs.append(Recommendation(title=title, detail=detail, priority=priority, category=category))

    if verdict == Verdict.BENIGN:
        add("benign", RecommendationPriority.LOW, RecommendationCategory.PREVENTION)
        add("monitor", RecommendationPriority.LOW, RecommendationCategory.PREVENTION)
        return recs[:limit]

    add(
        "do_not_engage",
        RecommendationPriority.IMMEDIATE if immediate else RecommendationPriority.HIGH,
        RecommendationCategory.CONTAINMENT,
    )
    if context.get("has_url"):
        add("no_link", RecommendationPriority.IMMEDIATE if immediate else RecommendationPriority.HIGH, RecommendationCategory.CONTAINMENT)
    if context.get("has_upi"):
        add("upi", RecommendationPriority.IMMEDIATE, RecommendationCategory.CONTAINMENT)
        add("bank", RecommendationPriority.HIGH, RecommendationCategory.VERIFICATION)
    if context.get("has_otp"):
        add("otp", RecommendationPriority.IMMEDIATE, RecommendationCategory.RECOVERY)
        add("bank", RecommendationPriority.HIGH, RecommendationCategory.RECOVERY)
    if context.get("has_attachment"):
        add("attachment", RecommendationPriority.HIGH, RecommendationCategory.CONTAINMENT)
    if context.get("module") == "email":
        add("email", RecommendationPriority.HIGH, RecommendationCategory.VERIFICATION)
    if context.get("module") == "visual" or "credential_harvest" in tags:
        add("credentials_site", RecommendationPriority.IMMEDIATE, RecommendationCategory.CONTAINMENT)
    add("report", RecommendationPriority.HIGH if immediate else RecommendationPriority.MEDIUM, RecommendationCategory.REPORTING)
    add("monitor", RecommendationPriority.MEDIUM, RecommendationCategory.PREVENTION)
    return recs[:limit]


def offline_summary(
    module: str,
    risk: RiskAssessment,
    findings: list[dict[str, Any]],
    context: dict[str, Any],
    language: str,
) -> tuple[str, str]:
    lang_code = _language_key(language)
    verdict = risk.verdict.value.replace("_", " ")
    top = [item.get("title", "") for item in findings[:3] if item.get("title")]
    technical = (
        f"Evidence-weighted risk is {risk.score}/100 ({verdict}); "
        f"{len(findings)} finding(s) were produced. "
        + ("Key findings: " + "; ".join(top) + ". " if top else "")
        + _details_in_english(context)
        + " All observations are linked to evidence identifiers in this report."
    )
    if lang_code == "hi":
        executive = (
            f"इस जाँच का जोखिम स्कोर {risk.score}/100 है और निष्कर्ष '{verdict}' है। "
            "निर्णय केवल इस रिपोर्ट में दर्ज साक्ष्यों पर आधारित है। "
            "नीचे दी गई सुरक्षा सलाह का पालन करें और किसी भी संदिग्ध लिंक, QR या भुगतान अनुरोध पर कार्रवाई न करें।"
        )
    elif lang_code == "bn":
        executive = (
            f"এই তদন্তের ঝুঁকি স্কোর {risk.score}/100 এবং সিদ্ধান্ত '{verdict}'। "
            "সিদ্ধান্তটি কেবল এই রিপোর্টে নথিভুক্ত প্রমাণের উপর ভিত্তি করে। "
            "নিচের নিরাপত্তা পরামর্শ অনুসরণ করুন এবং সন্দেহজনক লিংক, QR বা পেমেন্ট অনুরোধে সাড়া দেবেন না।"
        )
    elif lang_code == "hinglish":
        executive = (
            f"Is investigation ka risk score {risk.score}/100 hai aur verdict '{verdict}' hai. "
            "Yeh nirnay sirf is report mein darj evidence par based hai. "
            "Neeche diye gaye safety steps follow karein aur kisi bhi suspicious link, QR ya payment request par act na karein."
        )
    else:
        executive = (
            f"This investigation produced an evidence-weighted risk score of {risk.score}/100 "
            f"({verdict}). The verdict is based only on the observations recorded in this report. "
            f"{_details_in_english(context)} Follow the safety recommendations below, and do not "
            "act on the link, QR or payment request until it has been independently verified."
        )
    return executive, technical


EXPLAINER_SYSTEM = """You are a senior digital-fraud investigator writing for a non-technical victim.
You must:
1. Use ONLY the supplied findings, evidence summaries, risk factors and authentication results.
2. Never invent a domain, transaction, person or technical fact.
3. Explain WHY the evidence points to the verdict, citing evidence IDs in parentheses.
4. Give practical, safe recommendations. Never tell the user to open a suspicious link or pay.
5. Return one JSON object with keys: executive_summary (string), technical_summary (string),
   recommendations (array of objects with title, detail, priority in [immediate, high, medium, low],
   category in [containment, verification, reporting, prevention, recovery]).
6. Write in the requested language. Keep the executive summary under 140 words.
"""


class Explainer:
    def __init__(self, llm: LLMService | None) -> None:
        self.llm = llm

    async def explain(
        self,
        *,
        module: str,
        language: str,
        risk: RiskAssessment,
        findings: list[dict[str, Any]],
        evidence_digest: list[dict[str, Any]],
        context: dict[str, Any],
        brand: str | None = None,
    ) -> tuple[str, str, list[Recommendation], bool]:
        """Return (executive, technical, recommendations, used_llm)."""

        fallback_exec, fallback_tech = offline_summary(module, risk, findings, context, language)
        fallback_recs = build_recommendations(context, risk, language)
        if not self.llm or not self.llm.available or risk.verdict == Verdict.INCONCLUSIVE:
            return fallback_exec, fallback_tech, fallback_recs, False

        user = f"""Target language: {language_name(language)} ({language})
Module: {module}
Brand referenced: {brand or context.get('brand') or 'none'}
Verdict: {risk.verdict.value}
Risk score: {risk.score}/100
Severity: {risk.severity.value}
Risk factors: {[{'label': f['label'], 'weight': f['weight'], 'reason': f['reason']} for f in risk.factors[:12]]}
Findings: {[{'title': f.get('title'), 'severity': f.get('severity'), 'evidence_ids': f.get('evidence_ids'), 'description': truncate(str(f.get('description')), 500)} for f in findings[:12]]}
Evidence: {evidence_digest[:25]}
Context: {context}
Email authentication: {context.get('auth_summary', 'n/a')}
Safe deterministic recommendations already prepared (you may improve wording but must not contradict them): {[r.model_dump(mode='json') for r in fallback_recs]}
Return the JSON object now."""
        try:
            parsed, _response = await self.llm.json_chat(
                EXPLAINER_SYSTEM,
                user,
                max_tokens=1600,
                schema_hint=(
                    '{"executive_summary":"...","technical_summary":"...","recommendations":'
                    '[{"title":"...","detail":"...","priority":"immediate","category":"containment"}]}'
                ),
            )
        except LLMUnavailable as exc:
            logger.info("Explainer fell back to templates: %s", exc)
            return fallback_exec, fallback_tech, fallback_recs, False

        if not parsed:
            return fallback_exec, fallback_tech, fallback_recs, False
        executive = str(parsed.get("executive_summary") or "").strip()
        technical = str(parsed.get("technical_summary") or "").strip()
        if len(executive) < 40 or len(technical) < 20:
            return fallback_exec, fallback_tech, fallback_recs, False

        recommendations: list[Recommendation] = []
        for item in parsed.get("recommendations") or []:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "").strip()
            detail = str(item.get("detail") or "").strip()
            if not title or not detail:
                continue
            try:
                priority = RecommendationPriority(str(item.get("priority") or "medium").lower())
            except ValueError:
                priority = RecommendationPriority.MEDIUM
            try:
                category = RecommendationCategory(str(item.get("category") or "prevention").lower())
            except ValueError:
                category = RecommendationCategory.PREVENTION
            recommendations.append(
                Recommendation(title=truncate(title, 120), detail=truncate(detail, 500), priority=priority, category=category)
            )
            if len(recommendations) >= 6:
                break
        if not recommendations:
            recommendations = fallback_recs
        return truncate(executive, 1400), truncate(technical, 2600), recommendations, True
