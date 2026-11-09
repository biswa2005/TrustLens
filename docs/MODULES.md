# Modules — architecture, code, endpoints, agent communication, testing

Four investigation modules share one engine, one graph and one report format.
Each module owns a thin `schema/service/router` triple; the heavy lifting is
delegated to the LangGraph workflow.

```
app/modules/
├── common.py         # read_upload · validate_image · execute · envelope · safe_language
├── message/  schemas.py · service.py · router.py
├── qr/       service.py · router.py
├── visual/   service.py · router.py
└── email/    service.py · router.py
```

**Common pipeline (all modules)**

```
HTTP request ─► validate (Pydantic / upload caps) ─► service builds
  payload{serialisable} + artifacts{bytes/hints} + input_summary
      └► app/modules/common.py::execute()
            └► run_investigation(services, module, language, payload, artifacts, ...)
                  └► LangGraph ─► InvestigationReport ─► ReportEnvelope
```

`execute()` raises `500` if the workflow returned no report, embedding the
recorded `error`.

---

# 1 · Message / SMS module

**Purpose.** Multilingual (English, Hindi, Bengali, Hinglish) scam analysis:
scam category, psychological manipulation with quotes, entities (phone, VPA,
bank accounts), and link extraction for hand-off to the URL agent.

### 1.1 Architecture

```
POST /api/v1/messages/analyze
  └► message/router.py   (Pydantic validation)
      └► message/service.py::analyze   (payload + summary)
          └► common.execute(module="message")
              └► graph: orchestrator → message → [url] → evidence → report
                   message agent ──toolbox──► analyze_message, extract_urls
                   engine/text_signals.py     EN/HI/BN/Hinglish rules
                   engine/urls.py             URL + entity extraction
```

### 1.2 Folder / file explanations

| File | Role |
| --- | --- |
| `app/modules/message/schemas.py` | `MessageAnalysisRequest` — `text` (1–20000), `language`, `channel`, `sender`, `metadata` |
| `app/modules/message/service.py` | Builds the serialisable `payload` and the human `input_summary`, calls `execute()` |
| `app/modules/message/router.py` | `POST /messages/analyze` → `ReportEnvelope` |
| `app/agents/message_agent.py` | Specialist: plans `analyze_message` + `extract_urls`, merges signals/IOCs, raises phishing/KYC/OTP/job/loan/extortion findings and a manipulation finding with quotes |
| `app/engine/text_signals.py` | Transparent expert system: script detection (`Devanagari`/`Bengali`/`Latin`), Hinglish token detection, per-language `TacticRule`/`ScamRule` patterns, negation guard (protective phrases are not flagged), quoted manipulation evidence |
| `app/agents/orchestrator.py` | Adds URL work automatically when the text contains links |
| `app/agents/url_agent.py` | Studies every queued link (§5) |

### 1.3 Complete code

```python
# app/modules/message/schemas.py
from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field

class MessageAnalysisRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000,
                      description="The SMS/chat message body to investigate.")
    language: Literal["auto", "en", "hi", "bn", "hinglish"] = "auto"
    channel: Literal["sms", "whatsapp", "chat", "email", "other"] = "sms"
    sender: str | None = Field(default=None, max_length=200)
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional non-sensitive context (campaign, recipient segment, etc.).")
```

```python
# app/modules/message/service.py
from app.engine.utils import truncate
from app.modules.common import execute, safe_language
from app.modules.message.schemas import MessageAnalysisRequest
from app.schemas import InvestigationReport
from app.services import ForensicServices

async def analyze(services: ForensicServices, request: MessageAnalysisRequest
                  ) -> InvestigationReport:
    payload = request.model_dump()
    summary = (f"{request.channel.upper()} message"
               + (f" from {request.sender}" if request.sender else "")
               + f": {truncate(request.text, 240)}")
    return await execute(services=services, module="message",
                         language=safe_language(request.language),
                         payload=payload, artifacts={}, input_summary=summary)
```

```python
# app/modules/message/router.py
router = APIRouter(prefix="/messages", tags=["Message Investigation"])

@router.post("/analyze", response_model=ReportEnvelope,
             summary="Investigate a suspicious SMS, WhatsApp or chat message")
async def analyze_message(request: MessageAnalysisRequest,
                          services: ForensicServices = Depends(get_services)
                          ) -> ReportEnvelope:
    return envelope(await analyze(services, request))
```

### 1.4 Endpoint

```http
POST /api/v1/messages/analyze
Content-Type: application/json

{"text":"...","language":"auto|en|hi|bn|hinglish",
 "channel":"sms|whatsapp|chat|email|other","sender":"+91...","metadata":{}}
```
→ `200 ReportEnvelope` · `422` (empty/oversize text, bad language) · `500`.

### 1.5 Agent communication

1. **orchestrator → message**: `plan{primary:"message", agents:[message, url, evidence, report]}`.
2. **message → (state)**: `findings`, `signals`, `iocs`, `entities`,
   `agent_summaries`, and crucially `pending_urls=[...]` from `extract_urls`.
3. **router**: `_route_after_specialist` sees `pending_urls` → **url**.
4. **url → evidence → report**: infrastructure findings join the same finding
   list; `verification` gates them; the report scores everything together.
5. If links are missing from coverage, **evidence → url** can request up to 2
   rework passes via `requested_agents=["url"]`.

### 1.6 Testing

```bash
.venv\Scripts\python.exe -m pytest tests/test_modules.py -k message -v
curl -s localhost:8000/api/v1/messages/analyze -H "Content-Type: application/json" \
  -d @samples/message_sms.json | python -m json.tool | head -60
```
Also see `tests/test_engine.py::test_multilingual_detection_and_otp_tactics`
and `...::test_protective_phrase_is_not_flagged_as_otp_theft`.

---

# 2 · QR module

**Purpose.** Decode the QR image, classify the payload (UPI / URL / text /
Wi-Fi / vCard), explain UPI payment semantics and contradictions
("scan to *receive* money"), extract destination URLs for investigation.

### 2.1 Architecture

```
POST /api/v1/qr/analyze (multipart)
  └► qr/router.py: read_upload (MB cap)
      └► qr/service.py: validate_image (pixel cap) + payload + artifacts{image_bytes, caption}
          └► common.execute(module="qr")
              └► graph: orchestrator → qr → [url] → evidence → report
                   qr agent ──toolbox──► decode_qr · parse_upi · analyze_qr_context · extract_urls
                   engine/qr_utils.py      cv2 decode (multi-scale, ECC variants)
                   engine/urls.py           parse_upi_uri → warnings
```

### 2.2 File explanations

| File | Role |
| --- | --- |
| `app/modules/qr/service.py` | Pixel validation, payload construction, `artifacts={"image_bytes", "caption"}` |
| `app/modules/qr/router.py` | `POST /qr/analyze` — `image` file + `caption` + `language` form fields |
| `app/agents/qr_agent.py` | Specialist: decode → classify → UPI semantics → caption cross-check → queue embedded URLs |
| `app/engine/qr_utils.py` | OpenCV QRCodeDetector with scale/pyramid preprocessing, payload → `QRPayloadInfo` |
| `app/agents/toolbox.py` (`decode_qr`, `parse_upi`, `analyze_qr_context`) | Writes `qr_image`, `qr_payload`, `upi_uri` evidence + signals (`upi_payment_qr`, `upi_receive_lie`, …) |
| `app/engine/urls.py` (`parse_upi_uri`) | VPA syntax, amount/currency, known-handle vs brand-name mismatch, "receive/refund/prize" contradiction warnings |

**Guardrail:** if no payload could be decoded and the score is <20, the report
agent forces `verdict=inconclusive` — a QR image that was not decoded can never
be reported as *benign*.

### 2.3 Complete code

```python
# app/modules/qr/service.py
async def analyze(*, services, image_bytes, filename, content_type,
                  caption, language) -> InvestigationReport:
    settings = services.settings
    width, height, fmt = validate_image(image_bytes, settings.max_image_pixels)
    payload = {"filename": filename, "size": len(image_bytes),
               "content_type": content_type, "width": width, "height": height,
               "format": fmt, "caption": caption}
    summary = f"QR image '{filename}' ({width}×{height}, {fmt})"
    if caption:
        summary += f". User-supplied context: {truncate(caption, 200)}"
    return await execute(services=services, module="qr",
                         language=safe_language(language), payload=payload,
                         artifacts={"image_bytes": image_bytes, "caption": caption or ""},
                         input_summary=summary)
```

```python
# app/modules/qr/router.py
@router.post("/analyze", response_model=ReportEnvelope,
             summary="Decode a QR image and investigate its payment/URL semantics")
async def analyze_qr(
    image: Annotated[UploadFile, File(description="QR code image (PNG/JPEG/WebP)")],
    caption: Annotated[str | None, Form(description="Visible text or claim surrounding the QR code")] = None,
    language: Annotated[str, Form(description="auto|en|hi|bn|hinglish")] = "auto",
    services: ForensicServices = Depends(get_services),
) -> ReportEnvelope:
    raw = await read_upload(image, services.settings.max_upload_mb * 1024 * 1024,
                            kind="QR image")
    report = await analyze(services, image_bytes=raw,
                           filename=image.filename or "qr-image",
                           content_type=image.content_type,
                           caption=caption, language=language)
    return envelope(report)
```

### 2.4 Endpoint

```http
POST /api/v1/qr/analyze   multipart/form-data
  image  : file      (required, PNG/JPEG/WebP)
  caption: string    (optional — the surrounding claim)
  language: string   (optional)
```
→ `200 ReportEnvelope` · `422` unreadable image · `413` oversize/pixels.

### 2.5 Agent communication

1. **orchestrator → qr** with focus: *"Decode every QR payload and classify its
   semantics"*.
2. **qr → state**: `qr_payload`/`upi_uri` evidence, UPI + caption-contradiction
   signals, IOCs (`upi_id`, `url`), `pending_urls` for any embedded `http(s)` link.
3. **url → evidence → report**: UPI findings and infrastructure findings are
   merged; the risk engine caps payment and link categories independently.
4. **evidence → url**: rework if a queued URL was somehow not studied.

### 2.6 Testing

```bash
.venv\Scripts\python.exe -m pytest tests/test_modules.py -k qr -v
# unit: tests/test_engine.py::test_upi_refund_lie_is_explained
curl -s localhost:8000/api/v1/qr/analyze -F image=@samples/qrcode.png \
  -F "caption=Scan this QR to receive your refund" -F language=en
```
Expected findings: `UPI payment QR code`, `QR payment warnings`, plus
`upi_uri` evidence and a valid hash chain.

---

# 3 · Visual (website impersonation) module

**Purpose.** Detect brand impersonation and credential phishing in a screenshot
using a **vision-language model** plus **local OCR**, then verify the brand/domain
relationship with the brand registry and investigate any observed/claimed URL.

### 3.1 Architecture

```
POST /api/v1/visual/analyze (multipart)
  └► visual/router.py: read_upload
      └► visual/service.py: validate_image + artifacts{image_bytes, brand_hint, claimed_url}
          └► common.execute(module="visual")
              └► graph: orchestrator → visual → [url] → evidence → report
                   visual agent ──toolbox──► analyze_screenshot · local_ocr
                                                     · compare_brand_reference · extract_urls
                   engine/llm.py (VLM)    brand/layout/form/address-bar description
                   engine/image_utils.py  hashing, dimensions, format
                   engine/brands.py       official vs lookalike domain verdicts
```

### 3.2 File explanations

| File | Role |
| --- | --- |
| `app/modules/visual/service.py` | Pixel validation; passes `brand_hint`/`claimed_url` as both payload and artifacts |
| `app/modules/visual/router.py` | `POST /visual/analyze` — `image` + `brand_hint` + `claimed_url` + `language` |
| `app/agents/visual_agent.py` | Specialist: VLM observation → findings (brand impersonation, login/password forms, address-bar mismatch, HTTPS missing, lookalike domain, visual inconsistencies); explicit *"could not be visually analysed"* INFO finding when neither VLM nor OCR ran |
| `app/agents/toolbox.py` (`analyze_screenshot`, `local_ocr`, `compare_brand_reference`) | VLM call or OCR fallback → `vlm_observation` / `ocr_text` / `image_similarity` evidence; queues observed **and** claimed URLs |
| `app/engine/image_utils.py` | `basic_image evidence()` — sha256, dimensions, format |
| `app/data/brands.json` + `app/engine/brands.py` | Official domains, typosquat/homoglyph/subdomain rules |

**Guardrails**
* No `vlm_observation`/`ocr_text` **and** score <20 → `verdict=inconclusive`
  (never `benign`).
* Score ≥20 from other probative evidence (e.g. a lookalike URL) is kept.

### 3.3 Complete code

```python
# app/modules/visual/service.py
async def analyze(*, services, image_bytes, filename, content_type,
                  brand_hint, claimed_url, language) -> InvestigationReport:
    settings = services.settings
    width, height, fmt = validate_image(image_bytes, settings.max_image_pixels)
    payload = {"filename": filename, "size": len(image_bytes),
               "content_type": content_type, "width": width, "height": height,
               "format": fmt, "brand_hint": brand_hint, "claimed_url": claimed_url}
    summary = f"Website screenshot '{filename}' ({width}×{height}, {fmt})"
    if brand_hint:
        summary += f", claimed brand: {truncate(brand_hint, 80)}"
    if claimed_url:
        summary += f", claimed URL: {truncate(claimed_url, 160)}"
    return await execute(
        services=services, module="visual", language=safe_language(language),
        payload=payload,
        artifacts={"image_bytes": image_bytes, "brand_hint": brand_hint or "",
                   "claimed_url": claimed_url or ""},
        input_summary=summary)
```

```python
# app/modules/visual/router.py
@router.post("/analyze", response_model=ReportEnvelope,
             summary="Detect brand impersonation and credential phishing in a screenshot")
async def analyze_screenshot(
    image: Annotated[UploadFile, File(description="Website screenshot (PNG/JPEG/WebP)")],
    brand_hint: Annotated[str | None, Form(description="Brand the page appears to claim")] = None,
    claimed_url: Annotated[str | None, Form(description="URL shown in the screenshot or supplied by the user")] = None,
    language: Annotated[str, Form(description="auto|en|hi|bn|hinglish")] = "auto",
    services: ForensicServices = Depends(get_services),
) -> ReportEnvelope:
    raw = await read_upload(image, services.settings.max_upload_mb * 1024 * 1024,
                            kind="screenshot")
    report = await analyze(services, image_bytes=raw,
                           filename=image.filename or "screenshot",
                           content_type=image.content_type, brand_hint=brand_hint,
                           claimed_url=claimed_url, language=language)
    return envelope(report)
```

### 3.4 Endpoint

```http
POST /api/v1/visual/analyze   multipart/form-data
  image      : file   (required)
  brand_hint : string (optional)  e.g. "State Bank of India"
  claimed_url: string (optional)  e.g. https://sbi-secure-login.xyz/login
  language   : string (optional)
```

### 3.5 Agent communication

1. **orchestrator → visual** focus: *"OCR the page, including the address bar
   and form labels"*.
2. **visual → state**: `vlm_observation`/`ocr_text` evidence, visual findings,
   `pending_urls=[observed_url, claimed_url]`.
3. **url → evidence → report**: `Lookalike domain targets a brand`,
   `Suspicious infrastructure` findings merge with the visual findings — visual
   similarity and domain-ownership evidence stay separated, as required.
4. **evidence** re-checks grounding; **report** applies the incompleteness
   guardrail.

### 3.6 Testing

```bash
.venv\Scripts\python.exe -m pytest tests/test_modules.py -k visual -v
# test_visual_without_vision_is_not_falsely_benign      (offline → inconclusive)
# test_visual_investigates_claimed_lookalike_url        (URL evidence required)
curl -s localhost:8000/api/v1/visual/analyze \
  -F image=@samples/screenshot_login.png \
  -F "brand_hint=State Bank of India" \
  -F "claimed_url=https://sbi-secure-login.xyz/login"
```
With `HF_TOKEN` set the trace shows `analyze_screenshot` reasoning `ok`
instead of `skipped`, and `metadata.narrative_source=huggingface`.

---

# 4 · Email forensics module

**Purpose.** Parse an `.eml`, verify sender authentication **independently**
(SPF/DKIM/DMARC via DNS, not just header claims), detect BEC / invoice /
payment-change fraud, triage attachments statically (never execute), find
credential-harvesting HTML, and study body language and links.

### 4.1 Architecture

```
POST /api/v1/email/analyze (multipart)
  └► email/router.py: read_upload + RFC-822 sanity probe (from:/subject:)
      └► email/service.py: artifacts{eml_bytes}
          └► common.execute(module="email")
              └► graph: orchestrator → email → [url] → evidence → report
                   email agent ──toolbox──► parse_email  ▸  verify_email_auth   (order matters!)
                                                     · analyze_message (body) · extract_urls
                   engine/email_utils.py   MIME walk: headers, bodies, attachments, flags
                   engine/email_auth.py    independent SPF/DKIM/DMARC verification
                   engine/dns_ssl.py       DNS used for policy lookup (network mode)
```

### 4.2 File explanations

| File | Role |
| --- | --- |
| `app/modules/email/service.py` | Wraps `eml_bytes` into `artifacts`; minimal payload for reporting |
| `app/modules/email/router.py` | `POST /email/analyze`; enforces `min(MAX_EMAIL_BYTES, MAX_UPLOAD_MB)` and the RFC-822 probe |
| `app/agents/email_agent.py` | Findings groups: authentication (live failures / header-vs-live conflicts / unverified claims), identity mismatches, BEC, attachments, HTML deception, body analysis |
| `app/engine/email_utils.py` | Header parsing, address/Reply-To/Return-Path/Sender/Message-ID alignment, MIME walk with attachment static triage (double extension, macro/DDE, active PDF content), HTML password-form and link-text mismatch flags |
| `app/engine/email_auth.py` | SPF evaluation, DKIM/DMARC policy lookup + alignment; returns `enabled: false` with an explicit reason when the network or originating IP is unavailable → recorded as `not_verified` |
| `app/agents/toolbox.py` (`parse_email`, `verify_email_auth`) | Artifact cache (`parsed_email`) — `verify_email_auth` **requires** `parse_email` first |

**Auth honesty rules**
* `Authentication-Results` headers are treated as **claims**.
* Live results are authoritative; a claim of `pass` contradicting a live `fail`
  is a **critical** finding.
* Offline/unavailable → findings are labelled *unverified*, never "passed".

### 4.3 Complete code

```python
# app/modules/email/service.py
async def analyze(*, services, eml_bytes, filename, content_type,
                  language) -> InvestigationReport:
    payload = {"filename": filename, "size": len(eml_bytes),
               "content_type": content_type}
    return await execute(
        services=services, module="email", language=safe_language(language),
        payload=payload, artifacts={"eml_bytes": eml_bytes},
        input_summary=f"Uploaded email '{filename}' ({len(eml_bytes)} bytes)")
```

```python
# app/modules/email/router.py
@router.post("/analyze", response_model=ReportEnvelope,
             summary="Parse an EML file, verify SPF/DKIM/DMARC and investigate BEC/phishing")
async def analyze_email(
    eml: Annotated[UploadFile, File(description="Raw RFC 822 / .eml message")],
    language: Annotated[str, Form(description="auto|en|hi|bn|hinglish")] = "auto",
    services: ForensicServices = Depends(get_services),
) -> ReportEnvelope:
    limit = min(services.settings.max_email_bytes,
                services.settings.max_upload_mb * 1024 * 1024)
    raw = await read_upload(eml, limit, kind="email")
    probe = raw[:65_536].lower()
    if b"from:" not in probe and b"subject:" not in probe:
        raise HTTPException(status_code=422,
            detail="The uploaded file does not look like an RFC 822 / .eml message.")
    report = await analyze(services, eml_bytes=raw,
                           filename=eml.filename or "message.eml",
                           content_type=eml.content_type, language=language)
    return envelope(report)
```

```python
# app/agents/email_agent.py — tool ordering (the critical part)
def plan_tools(self, state, runtime):
    # ``parse_email`` must run first because ``verify_email_auth`` consumes the
    # parsed MIME object from the toolbox artifact cache.
    return [("parse_email", {}), ("verify_email_auth", {})]
```

### 4.4 Endpoint

```http
POST /api/v1/email/analyze   multipart/form-data
  eml      : file   (required, raw RFC 822)
  language : string (optional)
```
→ `200` · `422` non-EML · `413` oversize · `500` workflow failure.

### 4.5 Agent communication

1. **orchestrator → email** focus: header alignment, independent SPF/DKIM/DMARC,
   BEC assessment, static attachment triage.
2. **email → state**: `email_headers`/`email_body`/`email_attachment`/
   `email_auth` evidence, auth/identity/BEC/attachment/HTML/body findings,
   IOCs (email, URL, phone, brand), `pending_urls` from the body,
   `pending_domains` from the envelope (Reply-To / Return-Path).
3. **url → evidence → report**: the Reply-To and Return-Path domains are
   investigated like any other link, producing
   `Suspicious infrastructure: <domain>` findings next to the header findings.
4. **evidence**: chain verification + grounding; missing links trigger rework.
5. **report**: `metadata.email_auth` carries the authentication summary for the
   analyst (or `null` when verification never ran).

### 4.6 Testing

```bash
.venv\Scripts\python.exe -m pytest tests/test_modules.py -k email -v
# asserts: "business email compromise" · "authentication" in findings
#          email_auth + email_attachment evidence kinds present
curl -s localhost:8000/api/v1/email/analyze -F eml=@samples/bec_email.eml
curl -s -X POST localhost:8000/api/v1/investigations/<id>/verify   # chain check
```

---

# 5 · Shared pieces every module depends on

| Piece | File | Used for |
| --- | --- | --- |
| Upload & image validation | `app/modules/common.py` | MB/pixel caps, readable-image probe, RFC-822 probe |
| Language allow-list | `common.safe_language` | `auto\|en\|hi\|bn\|hinglish` only |
| Investigation entry point | `app/agents/graph.py::run_investigation` | isolated runtime per request |
| Evidence ledger | `app/engine/evidence.py` | HMAC chain, `verify_evidence_chain` |
| Risk engine | `app/engine/risk.py` | additive category-capped scoring |
| Explainer | `app/engine/explain.py` | grounded narrative (LLM or template) |
| Report builder/store | `app/engine/report.py` | JSON + Markdown + LRU retrieval |
| URL intelligence | `app/engine/url_investigator.py` | static+DNS+TLS+RDAP+intel+fetch |

---

# 6 · Cross-module testing instructions

```bash
# 1. offline test suite (no network, no token): 22 tests
.venv\Scripts\python.exe -m pytest

# 2. lint
.venv\Scripts\python.exe -m ruff check app tests

# 3. generate fixtures + run the live API
python scripts/generate_samples.py
python run.py                       # docs at http://127.0.0.1:8000/docs

# 4. exercise each module
curl -s localhost:8000/api/v1/messages/analyze -H "Content-Type: application/json" \
  -d @samples/message_sms.json
curl -s localhost:8000/api/v1/qr/analyze      -F image=@samples/qrcode.png \
  -F "caption=Scan to receive your refund"
curl -s localhost:8000/api/v1/visual/analyze  -F image=@samples/screenshot_login.png \
  -F "brand_hint=State Bank of India" -F claimed_url=https://sbi-secure-login.xyz/login
curl -s localhost:8000/api/v1/email/analyze   -F eml=@samples/bec_email.eml

# 5. verify integrity afterwards
curl -s localhost:8000/api/v1/investigations
curl -s -X POST localhost:8000/api/v1/investigations/<id>/verify
```

**What to check in every response**

1. `report.evidence_chain_valid === true`
2. every `findings[].evidence_ids` element exists in `report.evidence[].id`
3. `report.degraded === true` and `model.reasoning_mode === "offline-expert-system"`
   without a token (honest offline operation)
4. `agent_trace` reads `orchestrator → <specialist> → (url) → evidence → report`
5. visual/QR reports never claim `benign` when their core evidence is missing
6. `metadata.narrative_source` tells you which layer wrote the summary
