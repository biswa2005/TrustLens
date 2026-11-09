"""Multilingual message-signal extraction (English, Hindi, Bengali, Hinglish).

This module is a transparent expert system: curated phrase patterns produce
quoted, weighted observations.  It is not a trained classifier.  Generative
reasoning happens later, over these observations and live URL evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.engine.urls import extract_entities
from app.engine.utils import compact_whitespace, signal_id, truncate
from app.schemas import Severity, Signal, SignalCategory

DEVANAGARI_RE = re.compile(r"[\u0900-\u097F]")
BENGALI_RE = re.compile(r"[\u0980-\u09FF]")
LATIN_RE = re.compile(r"[A-Za-z]")

HINGLISH_TOKENS = {
    "aap", "aapka", "aapke", "aapki", "tum", "tumhara", "hai", "hain", "kya", "kyun",
    "kaise", "karo", "karein", "kijiye", "karna", "hoga", "hogi", "nahi", "mat", "abhi",
    "turant", "jaldi", "paise", "paisa", "rupaye", "kitna", "bhejo", "bhej", "batao",
    "milenge", "milega", "jeeta", "jeet", "inam", "khata", "khate", "band", "kholo",
    "link", "par", "click", "kare", "hu", "hoon", "gaya", "gayi", "wala", "wali",
    "bhai", "dost", "sahab", "ji", "please", "bhejie", "de", "do", "liye", "ke",
    "ki", "ka", "se", "ko", "mein", "me", "aur", "ya", "toh", "bhi",
}

_PROTECTIVE_RE = re.compile(
    r"(?i)(never|do not|don'?t|kabhi|kabhi bhi|mat)\s+(share|disclose|send|tell|batao|bhejo|share karein|share karo|bataye|batana)"
    r"|(कभी|कभी भी|मत|न)\s*(साझा|बताएं|बताइए|भेजें|शेयर)"
    r"|(কখনো|কখনও|না)\s*(শেয়ার|বলবেন|পাঠাবেন)"
)
_NEGATION_RE = re.compile(
    r"(?i)\b(never|not|no|don'?t|doesn'?t|won'?t|cannot|can'?t|kabhi nahi|mat)\b"
    r"|(?<![\u0900-\u097F])(कभी नहीं|नहीं|मत|न)(?![\u0900-\u097F])"
    r"|(?<![\u0980-\u09FF])(না|নয়|কখনো না)(?![\u0980-\u09FF])"
)


@dataclass(frozen=True)
class TacticRule:
    tactic: str
    label: str
    patterns: tuple[str, ...]
    weight: int
    severity: Severity
    category: SignalCategory
    scam_types: tuple[str, ...]
    explanation: str


RULES: tuple[TacticRule, ...] = (
    TacticRule(
        tactic="otp_request",
        label="OTP / verification-code request",
        patterns=(
            r"(?i)\b(?:share|send|tell|forward|read|provide|give|reveal|confirm)\b.{0,30}\b(?:otp|one[-\s]?time\s+password|verification\s+code|6[-\s]?digit\s+code|code)\b",
            r"(?i)\b(?:otp|verification\s+code|code)\b.{0,25}\b(?:share|batao|bhejo|bolo|de\s+do|send\s+me|tell\s+me)\b",
            r"(?:ओटीपी|ओ\s*टी\s*पी|वन\s*टाइम\s*पासवर्ड|सत्यापन\s*कोड).{0,30}(?:बताएं|बताइए|भेजें|शेयर|दें|बोलें|कन्फर्म)",
            r"(?i)\b(?:otp|code)\b.{0,20}(?:बताएं|बताइए|भेजें|शेयर|दें|बोलें|कन्फर्म)",
            r"(?:ওটিপি|ও\s*টি\s*পি|ভেরিফিকেশন\s*কোড).{0,30}(?:বলুন|পাঠান|শেয়ার|দিন|জানান)",
            r"(?i)\b(?:otp|code)\b.{0,20}(?:বলুন|পাঠান|শেয়ার|দিন|জানান)",
            r"(?i)\b(?:otp|code)\s+(?:batao|bhejo|bolo|share\s*karo|de\s*do)\b",
        ),
        weight=36,
        severity=Severity.CRITICAL,
        category=SignalCategory.CONTENT,
        scam_types=("otp_theft", "phishing", "bank_fraud"),
        explanation="A legitimate bank, exchange or service never asks you to disclose an OTP or verification code.",
    ),
    TacticRule(
        tactic="remote_access",
        label="Remote-access / screen-sharing request",
        patterns=(
            r"(?i)\b(anydesk|teamviewer|quick\s*support|rustdesk|screen\s*shar(?:e|ing)|remote\s*access|mirror\s*your\s*screen)\b",
            r"(?:स्क्रीन\s*शेयर|रिमोट\s*एक्सेस|कंट्रोल\s*कर|एनीडेस्क|टीमव्यूअर)",
            r"(?:স্ক্রিন\s*শেয়ার|রিমোট\s*অ্যাক্সেস|কন্ট্রোল\s*কর|অ্যানিডেস্ক|টিমভিউয়ার)",
        ),
        weight=32,
        severity=Severity.CRITICAL,
        category=SignalCategory.CONTENT,
        scam_types=("otp_theft", "tech_support_scam", "bank_fraud"),
        explanation="Remote-access tools let the caller see your screen and control your banking app.",
    ),
    TacticRule(
        tactic="credential_request",
        label="Credential, PIN or document harvesting",
        patterns=(
            r"(?i)\b(?:enter|provide|submit|confirm|update|verify)\b.{0,30}\b(?:password|pin\b|cvv|card\s*number|net\s*banking|username|login|aadhaar|aadhar|pan\s*card)\b",
            r"(?i)\b(?:login|sign\s*in|verify)\b.{0,25}\b(?:here|link|below|now)\b",
            r"(?:पासवर्ड|पिन|सीवीवी|कार्ड\s*नंबर|आधार|पैन|नेट\s*बैंकिंग).{0,25}(?:दर्ज|भरें|बताएं|अपडेट|सत्यापित)",
            r"(?:পাসওয়ার্ড|পিন|সিভিভি|কার্ড\s*নম্বর|আধার|প্যান|নেট\s*ব্যাংকিং).{0,25}(?:দিন|পূরণ|আপডেট|যাচাই)",
        ),
        weight=22,
        severity=Severity.HIGH,
        category=SignalCategory.CONTENT,
        scam_types=("phishing", "otp_theft", "kyc_fraud"),
        explanation="The message asks for secrets or identity documents that should only be entered on an official app or verified domain.",
    ),
    TacticRule(
        tactic="payment_request",
        label="Direct payment / transfer instruction",
        patterns=(
            r"(?i)\b(?:pay|send|transfer|deposit|remit)\b.{0,30}(?:₹|rs\.?|inr|\d{3,})",
            r"(?i)(?:₹|rs\.?|inr)\s?[\d,]{2,}.{0,35}\b(?:pay|send|transfer|upi|gpay|phonepe|paytm)\b",
            r"(?i)\b(?:upi|gpay|google\s*pay|phonepe|paytm|bhim)\b.{0,35}\b(?:send|transfer|pay|scan|request)\b",
            r"(?:भेजें|ट्रांसफर करें|भुगतान करें|स्कैन करें).{0,25}(?:₹|रुपये|रु\.?|\d{3,})",
            r"(?:পাঠান|ট্রান্সফার করুন|পেমেন্ট করুন|স্ক্যান করুন).{0,25}(?:₹|টাকা|\d{3,})",
            r"(?i)\b(?:pay|bhejo|transfer)\s+(?:karo|karein|kar\s+do|kar\s+dijiye)\b",
        ),
        weight=16,
        severity=Severity.HIGH,
        category=SignalCategory.PAYMENT,
        scam_types=("upi_fraud", "payment_fraud", "invoice_fraud"),
        explanation="The message directs a payment or transfer to a destination supplied by the sender.",
    ),
    TacticRule(
        tactic="payment_receive_lie",
        label="'Receive money by paying/scanning' contradiction",
        patterns=(
            r"(?i)\b(?:scan|pay|send)\b.{0,30}\b(?:to\s+)?(?:receive|get|collect)\b.{0,20}(?:money|cash|refund|₹|rs)",
            r"(?i)\b(?:receive|get)\b.{0,25}(?:₹|rs\.?|money).{0,30}\b(?:scan|pay|send)\b",
            r"(?i)\b(?:refund|cashback|reward)\b.{0,35}\b(?:scan|pay|send|upi|qr)\b",
            r"(?:पैसे|रिफंड|कैशबैक).{0,25}(?:पाने|प्राप्त).{0,25}(?:स्कैन|भेजें|भुगतान)",
            r"(?:টাকা|রিফান্ড|ক্যাশব্যাক).{0,25}(?:পেতে|পান).{0,25}(?:স্ক্যান|পাঠান|পেমেন্ট)",
        ),
        weight=30,
        severity=Severity.CRITICAL,
        category=SignalCategory.PAYMENT,
        scam_types=("upi_fraud", "refund_scam"),
        explanation="Scanning a UPI QR or approving a collect request debits your account. It cannot make money arrive.",
    ),
    TacticRule(
        tactic="job_fee",
        label="Up-front fee for a job",
        patterns=(
            r"(?i)\b(?:registration|joining|security|training|kit|membership|verification|processing)\s*(?:fee|charge|deposit|amount)\b",
            r"(?i)\b(?:work\s*from\s*home|part[-\s]?time\s*job|online\s*job|data\s*entry|copy\s*paste|typing\s*job)\b.{0,80}\b(?:registration|joining|training|kit|security|membership)\s*(?:fee|charge|deposit|amount)\b",
            r"(?:घर\s*बैठे|पार्ट\s*टाइम|ऑनलाइन\s*जॉब|डेटा\s*एंट्री).{0,60}(?:रजिस्ट्रेशन|जॉइनिंग|ट्रेनिंग)\s*(?:फीस|शुल्क|पैसे)",
            r"(?:রেজিস্ট্রেশন|জয়েনিং|ট্রেনিং)\s*(?:ফি|টাকা|চার্জ)",
            r"(?i)\b(?:registration|joining)\s+(?:fee|charge|ke\s+paisa|paise)\b",
        ),
        weight=26,
        severity=Severity.HIGH,
        category=SignalCategory.PAYMENT,
        scam_types=("fake_job", "advance_fee_fraud"),
        explanation="Legitimate employers do not charge candidates registration, kit or training fees.",
    ),
    TacticRule(
        tactic="job_lure",
        label="Work-from-home easy-earning lure",
        patterns=(
            r"(?i)\b(?:work\s*from\s*home|part[-\s]?time\s*job|online\s*job|data\s*entry|copy\s*paste|typing\s*job)\b",
            r"(?i)\b(?:earn|make)\b.{0,20}(?:₹|rs\.?|inr)?\s?\d{2,}.{0,20}\b(?:daily|per\s*day|weekly|monthly)\b",
            r"(?:घर\s*बैठे|पार्ट\s*टाइम|ऑनलाइन\s*जॉब|डेटा\s*एंट्री).{0,60}(?:कमाई|रोज|प्रतिदिन|हज़ार|लाख)",
            r"(?:ঘরে\s*বসে|পার্ট\s*টাইম|অনলাইন\s*কাজ).{0,60}(?:আয়|রোজ|হাজার|লাখ)",
            r"(?i)\b(?:ghar\s+baithe|daily\s+earning|roz\s+kamai)\b",
        ),
        weight=9,
        severity=Severity.MEDIUM,
        category=SignalCategory.CONTENT,
        scam_types=("fake_job",),
        explanation="Easy work-from-home income is a common recruitment lure and needs independent verification.",
    ),
    TacticRule(
        tactic="lottery_win",
        label="Unexpected prize / lottery win",
        patterns=(
            r"(?i)\b(?:you(?:'ve|\s+have)?\s+won|you\s+are\s+(?:the\s+)?(?:lucky\s+)?winner|congratulations.{0,25}(?:won|winner)|lucky\s+draw|jackpot|kbc)\b",
            r"(?:आपने|आप).{0,20}(?:जीता|जीती|इनाम|लॉटरी|लकी\s*ड्रॉ)",
            r"(?:পুরস্কার|লটারি|লাকি\s*ড্র|জিতেছেন)",
            r"(?i)\b(?:aapne|aap)\s+(?:jeeta|jeet\s+liya|inam)\b",
        ),
        weight=12,
        severity=Severity.MEDIUM,
        category=SignalCategory.CONTENT,
        scam_types=("lottery_scam",),
        explanation="An unexpected win that arrives without you entering a draw is a common lure.",
    ),
    TacticRule(
        tactic="lottery_fee",
        label="Prize release fee",
        patterns=(
            r"(?i)\b(?:processing|release|tax|clearance|courier|delivery|legal)\s+(?:fee|charge|amount)\b.{0,50}\b(?:prize|reward|winnings?|lottery|crore|lakh)\b",
            r"(?i)\b(?:prize|reward|winnings?|lottery|crore|lakh)\b.{0,50}\b(?:processing|release|tax|clearance|courier|delivery|legal)\s+(?:fee|charge|amount)\b",
            r"(?:इनाम|लॉटरी|पुरस्कार).{0,40}(?:फीस|शुल्क|टैक्स|कूरियर|प्रोसेसिंग)",
            r"(?:পুরস্কার|লটারি|জিতেছেন).{0,40}(?:ফি|টাকা|চার্জ|কর|কুরিয়ার)",
        ),
        weight=28,
        severity=Severity.HIGH,
        category=SignalCategory.PAYMENT,
        scam_types=("lottery_scam", "advance_fee_fraud"),
        explanation="A prize that requires an up-front fee, tax or courier payment is a classic advance-fee scam.",
    ),
    TacticRule(
        tactic="authority_impersonation",
        label="Fake authority / legal threat",
        patterns=(
            r"(?i)\b(?:police|cbi|ncb|enforcement\s+directorate|income\s+tax|customs|court|judge|rbi|trai|telecom\s+department|cyber\s+cell)\b.{0,60}\b(?:case|fir|arrest|warrant|fine|penalty|notice|block|verify|courier|drugs|money\s+laundering)\b",
            r"(?i)\bdigital\s+arrest\b",
            r"(?:पुलिस|सीबीआई|अदालत|न्यायालय|आयकर|सीमा\s*शुल्क|साइबर\s*सेल).{0,50}(?:गिरफ्तारी|केस|नोटिस|जुर्माना|वारंट|ब्लॉक)",
            r"(?:পুলিশ|সিবিআই|আদালত|আয়কর|শুল্ক|সাইবার\s*সেল).{0,50}(?:গ্রেপ্তার|মামলা|নোটিশ|জরিমানা|ওয়ারেন্ট|ব্লক)",
        ),
        weight=24,
        severity=Severity.HIGH,
        category=SignalCategory.IDENTITY,
        scam_types=("authority_impersonation", "digital_arrest", "extortion"),
        explanation="Real agencies communicate through official notices and never demand instant payment or secrecy over a call.",
    ),
    TacticRule(
        tactic="account_threat",
        label="Account/service suspension threat",
        patterns=(
            r"(?i)\b(?:account|sim|number|service|connection|card)\b.{0,30}\b(?:will\s+be|has\s+been|is)\b.{0,20}\b(?:blocked|suspended|deactivated|disconnected|terminated|frozen|closed)\b",
            r"(?i)\b(?:blocked|suspended|deactivated|disconnected|terminated)\b.{0,30}\b(?:within|in)\s+\d+\s*(?:hours?|minutes?)\b",
            r"(?:खाता|खाते|सिम|नंबर|सेवा).{0,30}(?:बंद|निलंबित|ब्लॉक|बंद हो जाएगा|कट जाएगा)",
            r"(?:অ্যাকাউন্ট|সিম|নম্বর|সেবা).{0,30}(?:বন্ধ|স্থগিত|ব্লক|বন্ধ হয়ে যাবে)",
            r"(?i)\b(?:account|sim)\s+(?:band|block)\s+(?:ho\s+jayega|hoga)\b",
        ),
        weight=14,
        severity=Severity.HIGH,
        category=SignalCategory.PRESSURE,
        scam_types=("phishing", "kyc_fraud", "telecom_scam"),
        explanation="Artificial suspension deadlines pressure the recipient to act before verifying the claim.",
    ),
    TacticRule(
        tactic="urgency",
        label="Urgency / artificial deadline",
        patterns=(
            r"(?i)\b(?:immediately|urgent(?:ly)?|right\s+now|within\s+\d+\s*(?:minutes?|hours?)|last\s+chance|final\s+warning|expires?\s+(?:today|soon|in)|act\s+now|hurry|today\s+only)\b",
            r"(?:तुरंत|फौरन|आज\s*ही|जल्दी|जल्द|अंतिम|शीघ्र|समय\s*सीमा|आखिरी\s*मौका)",
            r"(?:এখনই|দ্রুত|আজই|শেষ\s*সুযোগ|সময়সীমা|শীঘ্রই)",
            r"(?i)\b(?:turant|jaldi|abhi|aaj\s*hi|last\s*chance)\b",
        ),
        weight=8,
        severity=Severity.MEDIUM,
        category=SignalCategory.PRESSURE,
        scam_types=("phishing", "upi_fraud", "fake_job", "lottery_scam"),
        explanation="A short, artificial deadline discourages independent verification.",
    ),
    TacticRule(
        tactic="fear",
        label="Fear, penalty or legal consequence",
        patterns=(
            r"(?i)\b(?:legal\s+action|arrest\s+warrant|lawsuit|case\s+(?:will\s+be\s+)?filed|fine|penalty|prosecution|criminal\s+case)\b",
            r"(?i)\b(?:your\s+)?(?:money|funds?|salary|pension)\b.{0,30}\b(?:will\s+be\s+)?(?:forfeited|frozen|held|deducted)\b",
            r"(?:कानूनी\s*कार्रवाई|गिरफ्तारी|जुर्माना|मुकदमा|केस\s*दर्ज|पेनल्टी)",
            r"(?:আইনি\s*ব্যবস্থা|গ্রেপ্তার|জরিমানা|মামলা|পেনাল্টি)",
        ),
        weight=12,
        severity=Severity.HIGH,
        category=SignalCategory.PRESSURE,
        scam_types=("authority_impersonation", "extortion", "digital_arrest"),
        explanation="Threats of arrest, fines or frozen funds are used to override careful thinking.",
    ),
    TacticRule(
        tactic="secrecy",
        label="Secrecy instruction",
        patterns=(
            r"(?i)\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|share\s+with|discuss\s+with)\b.{0,30}\b(?:bank|family|friend|anyone|police|staff)\b",
            r"(?i)\b(?:keep|maintain)\b.{0,20}\b(?:confidential|secret)\b",
            r"(?:किसी\s*को|बैंक\s*को|परिवार\s*को).{0,20}(?:न\s*बताएं|मत\s*बताइए|गुप्त\s*रखें)",
            r"(?:কাউকে|ব্যাংককে|পরিবারকে).{0,20}(?:বলবেন\s*না|গোপন\s*রাখুন)",
        ),
        weight=20,
        severity=Severity.HIGH,
        category=SignalCategory.PRESSURE,
        scam_types=("authority_impersonation", "digital_arrest", "bank_fraud"),
        explanation="Requests for secrecy prevent the victim from getting a second opinion — a hallmark of fraud.",
    ),
    TacticRule(
        tactic="greed",
        label="Unrealistic reward or easy money",
        patterns=(
            r"(?i)\b(?:free|guaranteed|instant|double\s+your|risk[-\s]?free)\b.{0,25}\b(?:money|income|profit|return|gift|reward|cashback|bonus)\b",
            r"(?i)\b(?:earn|make)\b.{0,15}(?:₹|rs\.?|inr)?\s?\d{2,}.{0,15}\b(?:daily|per\s*day|weekly|monthly)\b",
            r"(?:मुफ्त|गारंटी|डबल|बिना\s*निवेश).{0,25}(?:पैसा|कमाई|मुनाफा|इनाम|गिफ्ट)",
            r"(?:বিনামূল্যে|গ্যারান্টি|দ্বিগুণ|বিনিয়োগ\s*ছাড়া).{0,25}(?:টাকা|আয়|লাভ|পুরস্কার)",
        ),
        weight=8,
        severity=Severity.MEDIUM,
        category=SignalCategory.CONTENT,
        scam_types=("investment_scam", "lottery_scam", "fake_job"),
        explanation="Unrealistic returns are used to attract a victim before a fee or deposit is requested.",
    ),
    TacticRule(
        tactic="generic_greeting",
        label="Generic, non-personalised greeting",
        patterns=(
            r"(?i)\b(?:dear\s+(?:customer|user|member|sir/madam|valued\s+customer)|dear\s+candidate)\b",
            r"(?:प्रिय\s*(?:ग्राहक|उपयोगकर्ता|सदस्य))",
            r"(?:প্রিয়\s*(?:গ্রাহক|সদস্য))",
        ),
        weight=4,
        severity=Severity.LOW,
        category=SignalCategory.CONTENT,
        scam_types=("phishing", "fake_job"),
        explanation="A generic greeting suggests a bulk campaign rather than a genuine personal message.",
    ),
    TacticRule(
        tactic="link_pressure",
        label="Push to click an unverified link",
        patterns=(
            r"(?i)\b(?:click|tap|open|visit)\b.{0,20}\b(?:here|link|below|button)\b",
            r"(?i)\b(?:verify|login|update|claim|pay)\b.{0,20}\b(?:at|via|through)\s+(?:this|the)\s+link\b",
            r"(?:लिंक|नीचे).{0,15}(?:क्लिक|खोलें|दबाएं)",
            r"(?:লিংক|নিচে).{0,15}(?:ক্লিক|খুলুন)",
        ),
        weight=7,
        severity=Severity.MEDIUM,
        category=SignalCategory.LINK,
        scam_types=("phishing",),
        explanation="The message wants you to leave the messaging app and act on a link controlled by the sender.",
    ),
    TacticRule(
        tactic="payment_channel",
        label="Unusual payment channel",
        patterns=(
            r"(?i)\b(?:gift\s*card|amazon\s*gift|google\s*play\s*(?:card|code)|itunes\s*card|steam\s*card|crypto|bitcoin|usdt|trc20)\b",
            r"(?i)\b(?:bank\s*account|a/c\s*(?:no|number)|account\s*number|ifsc|beneficiary)\b",
        ),
        weight=10,
        severity=Severity.MEDIUM,
        category=SignalCategory.PAYMENT,
        scam_types=("bec", "invoice_fraud", "payment_fraud"),
        explanation="Gift cards, crypto or newly supplied bank details are hard to reverse and common in fraud.",
    ),
    TacticRule(
        tactic="delivery_fee",
        label="Fake delivery/customs fee",
        patterns=(
            r"(?i)\b(?:parcel|courier|package|shipment|delivery|consignment)\b.{0,50}\b(?:held|customs|failed|pending|fee|charge|address|redelivery)\b",
            r"(?:पार्सल|कूरियर|डिलीवरी|शिपमेंट).{0,40}(?:रुका|सीमा\s*शुल्क|फीस|पता|विफल)",
            r"(?:পার্সেল|কুরিয়ার|ডেলিভারি).{0,40}(?:ফি|চার্জ|ঠিকানা|ব্যর্থ)",
        ),
        weight=12,
        severity=Severity.MEDIUM,
        category=SignalCategory.CONTENT,
        scam_types=("delivery_scam", "phishing"),
        explanation="Unexpected parcel/customs fees are used to harvest payment details or a small payment.",
    ),
    TacticRule(
        tactic="kyc_pressure",
        label="KYC/account-update pressure",
        patterns=(
            r"(?i)\b(?:kyc|know\s+your\s+customer|pan\s*card|aadhaar)\b.{0,40}\b(?:update|pending|expire|complete|link|verify|block)\b",
            r"(?:केवाईसी|केवाईसी\s*अपडेट|पैन\s*कार्ड|आधार).{0,35}(?:अपडेट|लंबित|समाप्त|सत्यापित|ब्लॉक|लिंक)",
            r"(?:কেওয়াইসি|প্যান\s*কার্ড|আধার).{0,35}(?:আপডেট|মেয়াদ|যাচাই|ব্লক|লিংক)",
            r"(?i)\bkyc\s+(?:update|pending|expire|complete|kar(?:o|ein|na))\b",
        ),
        weight=14,
        severity=Severity.HIGH,
        category=SignalCategory.IDENTITY,
        scam_types=("kyc_fraud", "phishing"),
        explanation="KYC deadlines are frequently impersonated to harvest identity documents and banking credentials.",
    ),
    TacticRule(
        tactic="investment_pitch",
        label="High-return investment pitch",
        patterns=(
            r"(?i)\b(?:guaranteed|assured|fixed)\b.{0,20}\b(?:return|profit|income)\b.{0,20}\b\d{1,3}\s?%",
            r"(?i)\b(?:invest|deposit)\b.{0,25}(?:₹|rs\.?|inr)\s?[\d,]{3,}.{0,30}\b(?:profit|return|double|daily|weekly)\b",
            r"(?i)\b(?:trading\s+(?:group|signal|tips)|forex|binary\s+options|sip\s+plan)\b.{0,40}\b(?:telegram|whatsapp|guaranteed|profit|return)\b",
            r"(?:निवेश|ट्रेडिंग|मुनाफा|गारंटीशुदा\s*रिटर्न).{0,35}(?:गारंटी|डबल|प्रतिदिन|मुनाफा|टेलीग्राम)",
            r"(?i)\b(?:telegram|whatsapp)\b.{0,25}\b(?:trading|investment|profit|signal)\b",
        ),
        weight=18,
        severity=Severity.HIGH,
        category=SignalCategory.CONTENT,
        scam_types=("investment_scam", "pig_butchering"),
        explanation="Guaranteed high returns promoted through chat groups are a strong investment-fraud indicator.",
    ),
    TacticRule(
        tactic="romance_advance",
        label="Relationship plus money request",
        patterns=(
            r"(?i)\b(?:my\s+(?:love|dear|darling)|i\s+love\s+you)\b.{0,120}\b(?:money|transfer|gift|customs|hospital|fee|bitcoin)\b",
            r"(?i)\b(?:met\s+online|never\s+met|video\s+call\s+(?:failed|not\s+working))\b.{0,120}\b(?:money|fee|transfer)\b",
        ),
        weight=16,
        severity=Severity.HIGH,
        category=SignalCategory.PRESSURE,
        scam_types=("romance_scam",),
        explanation="An online relationship that turns into a money request is a common long-con pattern.",
    ),
    TacticRule(
        tactic="obfuscated_otp",
        label="Obfuscated sensitive keyword",
        patterns=(
            r"(?i)\b[o0][\s._\-*]{1,3}t[\s._\-*]{1,3}p\b",
            r"(?i)\b[a@][\s._\-*]{1,3}c[\s._\-*]{1,3}c[\s._\-*]{1,3}o[\s._\-*]{1,3}u[\s._\-*]{1,3}n[\s._\-*]{1,3}t\b",
        ),
        weight=12,
        severity=Severity.HIGH,
        category=SignalCategory.OBFUSCATION,
        scam_types=("otp_theft", "phishing"),
        explanation="Sensitive words are deliberately spaced or substituted to evade keyword filters.",
    ),
)

_COMPILED = tuple(
    (rule, tuple(re.compile(pattern, re.UNICODE) for pattern in rule.patterns)) for rule in RULES
)


@dataclass
class TextAnalysis:
    language: str
    script: str
    language_confidence: float
    signals: list[Signal] = field(default_factory=list)
    scam_types: list[dict[str, Any]] = field(default_factory=list)
    manipulation: list[dict[str, Any]] = field(default_factory=list)
    protective_phrases: list[str] = field(default_factory=list)
    entities: dict[str, list[str]] = field(default_factory=dict)
    word_count: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "script": self.script,
            "language_confidence": self.language_confidence,
            "scam_types": self.scam_types,
            "manipulation": self.manipulation,
            "protective_phrases": self.protective_phrases,
            "entities": self.entities,
            "word_count": self.word_count,
            "notes": self.notes,
            "signals": [signal.model_dump(mode="json") for signal in self.signals],
        }


def detect_language(text: str, requested: str = "auto") -> tuple[str, str, float]:
    devanagari = len(DEVANAGARI_RE.findall(text))
    bengali = len(BENGALI_RE.findall(text))
    latin = len(LATIN_RE.findall(text))
    total_script = devanagari + bengali + latin
    if requested and requested not in {"auto", ""}:
        script = (
            "Devanagari" if requested == "hi" else "Bengali" if requested == "bn" else "Latin"
        )
        return requested, script, 0.99
    if bengali > max(devanagari, latin * 0.6) and bengali > 3:
        return "bn", "Bengali", round(min(0.98, 0.55 + bengali / max(1, total_script)), 2)
    if devanagari > max(bengali, latin * 0.35) and devanagari > 3:
        return "hi", "Devanagari", round(min(0.98, 0.55 + devanagari / max(1, total_script)), 2)
    words = set(re.findall(r"[a-z]+", text.lower()))
    hinglish_hits = len(words & HINGLISH_TOKENS)
    if hinglish_hits >= 2 and latin > 10:
        return "hinglish", "Latin", round(min(0.95, 0.55 + hinglish_hits / max(4, len(words))), 2)
    return "en", "Latin", 0.8 if latin > 5 else 0.5


def _is_negated(text: str, start: int, end: int) -> bool:
    window = text[max(0, start - 45) : min(len(text), end + 45)]
    return bool(_NEGATION_RE.search(window))


def _quote_window(text: str, start: int, end: int, *, before: int, after: int) -> str:
    """Return a readable quote around ``[start, end)``.

    A raw character window can begin or end mid-word — worst case inside a URL
    (``rs.sbi.co.in. Never share …``), which reads as gibberish in a report.
    The head is therefore snapped forward to the nearest sentence boundary when
    one is close, otherwise to a word boundary; the tail is never cut halfway
    through a word.
    """
    lo = max(0, start - before)
    hi = min(len(text), end + after)
    prefix = text[lo:start]
    boundary: tuple[int, int] | None = None
    for marker in (". ", "! ", "? ", "\n", "। ", "।"):
        idx = prefix.rfind(marker)
        if idx != -1 and (boundary is None or idx > boundary[0]):
            boundary = (idx, len(marker))
    if boundary is not None:
        lo += boundary[0] + boundary[1]
    elif lo > 0 and not text[lo - 1].isspace():
        # No sentence break nearby: drop the partially captured leading word.
        while lo < start and not text[lo].isspace():
            lo += 1
    if hi < len(text) and not text[hi].isspace() and not text[hi - 1].isspace():
        stop = text.find(" ", hi)
        if stop != -1 and stop <= hi + 30:
            hi = stop
    return compact_whitespace(text[lo:hi])


def analyze_message_text(
    text: str,
    *,
    language: str = "auto",
    channel: str = "sms",
    sender: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> TextAnalysis:
    metadata = metadata or {}
    language_code, script, language_confidence = detect_language(text, language)
    analysis = TextAnalysis(
        language=language_code,
        script=script,
        language_confidence=language_confidence,
        word_count=len(re.findall(r"\S+", text)),
    )
    analysis.entities = extract_entities(text)

    matched_spans: set[tuple[str, int, int]] = set()
    type_support: dict[str, list[dict[str, Any]]] = {}
    tactic_seen: dict[str, int] = {}

    for rule, patterns in _COMPILED:
        if tactic_seen.get(rule.tactic, 0) >= 2:
            continue
        for pattern in patterns:
            for match in pattern.finditer(text):
                start, end = match.span()
                if end - start < 2:
                    continue
                if _is_negated(text, start, end):
                    quote = _quote_window(text, start, end, before=60, after=30)
                    analysis.protective_phrases.append(truncate(quote, 180))
                    continue
                if rule.tactic == "authority_impersonation":
                    window = text[max(0, start - 120) : min(len(text), end + 160)]
                    if not re.search(
                        r"(?i)\b(?:you|your|yours|aap|aapke|tum|tumhare)\b|आप|आपके|তুমি|আপনি|আপনার",
                        window,
                    ):
                        continue
                key = (rule.tactic, start, end)
                if key in matched_spans:
                    continue
                matched_spans.add(key)
                tactic_seen[rule.tactic] = tactic_seen.get(rule.tactic, 0) + 1
                quote = _quote_window(text, start, end, before=60, after=60)
                signal = Signal(
                    id=signal_id("msg", rule.tactic, str(start), str(end), text[start:end]),
                    category=rule.category,
                    label=rule.label,
                    description=f"{rule.explanation} Quoted evidence: “{truncate(quote, 220)}”",
                    weight=rule.weight,
                    severity=rule.severity,
                    confidence=0.86,
                    source=f"text-lexicon:{rule.tactic}",
                )
                analysis.signals.append(signal)
                analysis.manipulation.append(
                    {
                        "tactic": rule.tactic,
                        "label": rule.label,
                        "quote": truncate(quote, 240),
                        "explanation": rule.explanation,
                        "severity": rule.severity.value,
                        "weight": rule.weight,
                    }
                )
                for scam_type in rule.scam_types:
                    type_support.setdefault(scam_type, []).append(
                        {"tactic": rule.tactic, "weight": rule.weight, "signal_id": signal.id}
                    )
                break  # one match per pattern is enough

    # Entity-based, high-value observations (UPI IDs and amounts in the same message)
    entities = analysis.entities
    if entities.get("upi_ids"):
        has_payment_language = any(
            hit["tactic"] in {"payment_request", "payment_receive_lie", "payment_channel"}
            for hit in analysis.manipulation
        )
        weight = 18 if has_payment_language else 8
        signal = Signal(
            id=signal_id("msg", "upi_id_present", ",".join(entities["upi_ids"])),
            category=SignalCategory.PAYMENT,
            label="UPI payment address in message",
            description=(
                "The message contains a UPI address: "
                + ", ".join(entities["upi_ids"][:4])
                + ". Verify the payee independently in your own payment app."
            ),
            weight=weight,
            severity=Severity.HIGH if has_payment_language else Severity.MEDIUM,
            confidence=0.9,
            source="entity-extractor:upi",
        )
        analysis.signals.append(signal)
        type_support.setdefault("upi_fraud", []).append(
            {"tactic": "upi_id_present", "weight": weight, "signal_id": signal.id}
        )

    if metadata.get("forwarded") and channel in {"whatsapp", "sms"}:
        analysis.notes.append("Message is marked as forwarded many times.")

    # Summarise scam types, with confidence tied to independent supporting tactics.
    for scam_type, supports in type_support.items():
        tactics = {item["tactic"] for item in supports}
        max_weight = max(item["weight"] for item in supports)
        # Base must stay below the 0.45 reporting gate for a *single weak*
        # tactic: one generic greeting (weight 4) alone gives 0.39 and must not
        # headline a "consistent with phishing" finding, while a single strong
        # tactic (e.g. OTP request, weight 36) still reaches 0.66 on its own.
        confidence = min(0.96, 0.25 + 0.11 * len(tactics) + max_weight / 120)
        analysis.scam_types.append(
            {
                "type": scam_type,
                "confidence": round(confidence, 2),
                "supporting_tactics": sorted(tactics),
                "signal_ids": [item["signal_id"] for item in supports],
            }
        )
    analysis.scam_types.sort(key=lambda item: item["confidence"], reverse=True)

    # De-duplicate identical signal ids introduced by multiple patterns.
    unique: dict[str, Signal] = {}
    for signal in analysis.signals:
        unique[signal.id] = signal
    analysis.signals = sorted(unique.values(), key=lambda item: item.weight, reverse=True)
    return analysis
