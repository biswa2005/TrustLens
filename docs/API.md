# HTTP API Reference

Base URL: `http://127.0.0.1:8000` · Prefix: **`/api/v1`** (`API_PREFIX`) ·
Interactive docs: **`/docs`** (Swagger UI) and **`/redoc`**.

There is **no authentication layer** in this build — put it behind your gateway.

---

## 1. Endpoint index

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | redirect → `/docs` |
| GET | `/health` | minimal liveness (no services access) |
| GET | `/api/v1/health` | liveness + reasoning mode + degraded flag |
| GET | `/api/v1/meta` | modules, agents, models, limits, providers |
| POST | `/api/v1/messages/analyze` | investigate an SMS/WhatsApp/chat message |
| POST | `/api/v1/qr/analyze` | decode + investigate a QR image |
| POST | `/api/v1/visual/analyze` | investigate a website screenshot |
| POST | `/api/v1/email/analyze` | investigate a raw `.eml` message |
| GET | `/api/v1/investigations` | list stored reports |
| GET | `/api/v1/investigations/{id}` | full report (JSON) |
| GET | `/api/v1/investigations/{id}/markdown` | report as Markdown |
| POST | `/api/v1/investigations/{id}/verify` | recompute the evidence hash chain |

---

## 2. Common response envelope

Every `*/analyze` endpoint returns `200 OK` with:

```jsonc
{
  "investigation_id": "inv_638b696f6b7ac3a3",
  "module": "message",                 // message | qr | visual | email
  "report": { /* InvestigationReport, see §3 */ }
}
```

### Error model

Errors use FastAPI's standard shape: `{"detail": "<message>"}`.

| Status | When |
| --- | --- |
| `404` | unknown `investigation_id` (all three report endpoints) |
| `413` | upload exceeds `MAX_UPLOAD_MB`, image exceeds `MAX_IMAGE_PIXELS`, email exceeds `MAX_EMAIL_BYTES` |
| `422` | Pydantic validation failure, empty upload, unreadable image, non-EML file, unknown `module` filter, `language` outside `auto/en/hi/bn/hinglish` |
| `500` | workflow produced no report (`detail` includes the recorded `error`) |

---

## 3. `InvestigationReport` (the payload you will consume)

```jsonc
{
  "id": "inv_...",
  "module": "message",
  "created_at": "2026-11-08T10:12:03+00:00",
  "completed_at": "2026-11-08T10:12:04+00:00",
  "language": "en",
  "input_summary": "SMS from +919999999999: URGENT: Your SBI account...",

  "verdict": "malicious",              // benign|suspicious|likely_malicious|malicious|inconclusive
  "severity": "critical",              // info|low|medium|high|critical
  "risk_score": 100,                   // 0-100
  "confidence": 0.86,

  "executive_summary": "...",          // non-technical narrative
  "technical_summary": "...",          // evidence-oriented narrative

  "risk": {
    "score": 100, "severity": "critical", "verdict": "malicious",
    "confidence": 0.86,
    "category_scores": { "identity": 30, "link": 35, "pressure": 30, "content": 5 },
    "factors": [
      { "id": "brand_typosquat", "label": "Possible brand impersonation",
        "category": "identity", "weight": 28,
        "reason": "...", "evidence_ids": ["ev_51609c82b337536b"] }
    ],
    "summary": "...", "confidence_basis": "...", "evidence_coverage": 1.0
  },

  "findings": [
    { "id": "fnd_...", "agent": "message", "title": "Message consistent with phishing",
      "description": "...", "severity": "high", "confidence": 0.9,
      "evidence_ids": ["ev_..."],                 // always ⊆ evidence[].id
      "techniques": ["T1566 Phishing"], "tags": ["phishing", "otp_theft"] }
  ],

  "evidence": [                          // append-only, hash-chained ledger
    { "id": "ev_...", "kind": "message_signal", "source": "analyze_message",
      "summary": "...", "data": { },
      "confidence": 0.9, "verified": true,
      "collected_at": "...",
      "sha256": "...", "prev_hash": "...", "chain_hash": "..." }
  ],

  "recommendations": [
    { "title": "Do not click the link", "detail": "...",
      "priority": "immediate", "category": "containment" }
  ],
  "iocs": [
    { "type": "url", "value": "http://sbi-kyc-verify.xyz/login",
      "risk": "high", "context": "...", "evidence_ids": ["ev_..."] }
  ],
  "entities": { "brand": "SBI", "sender": "+919999999999" },

  "agent_trace": [                      // the audit log
    { "agent": "orchestrator", "step": "plan", "action": "Investigation plan selected",
      "tool": null, "detail": "message → url → evidence → report",
      "status": "ok", "latency_ms": 0, "model": null }
  ],
  "plan": { "primary": "message", "agents": ["message","url","evidence","report"],
            "rationale": "...", "focus": [...], "depth": "standard",
            "mode": "offline-planner" },

  "model": { "text_model": "Qwen/Qwen2.5-72B-Instruct",
             "vision_model": "Qwen/Qwen2.5-VL-72B-Instruct",
             "reasoning_mode": "offline-expert-system",
             "degraded": true, "providers": [], "notes": "..." },

  "metadata": {
    "verification": { "chain_valid": true, "dropped_finding_ids": [], "notes": [...] },
    "agent_summaries": [ { "agent": "message", "summary": "...", "findings": 3 } ],
    "plan": { }, "evidence_fingerprint": "65c6...", "evidence_count": 8,
    "investigation_completeness": 1.0,
    "narrative_source": "deterministic-template",   // or "huggingface"
    "reasoning_mode": "offline-expert-system", "degraded": true,
    "email_auth": { ... },            // email module only
    "risk_confidence_basis": "...", "limitations": [ "..." ]
  },

  "evidence_chain_valid": true,
  "degraded": true,
  "markdown": "# ThreatLens Investigation Report\n...",
  "report_version": "1.0",
  "evidence_count": 8                  // computed field
}
```

**Reading a report responsibly**

* `degraded=true` ⇒ no model produced the narrative; the deterministic expert
  system did. Check `metadata.narrative_source` for which layer wrote the text.
* `verdict=inconclusive` ⇒ the evidence needed for a verdict was absent (e.g.
  no VLM/OCR observation for a screenshot, no decodable QR payload).
* `evidence_chain_valid=false` ⇒ do not trust the report; investigate.

---

## 4. Service endpoints

### `GET /api/v1/health`
```json
{"status":"ok","app":"ThreatLens","version":"1.0.0","environment":"development",
 "reasoning_mode":"offline-expert-system","degraded":true,
 "network_enabled":false,"reports_cached":4}
```
`reasoning_mode` ∈ `huggingface` · `offline-expert-system`.

### `GET /api/v1/meta`
Returns `app`, `version`, `modules{}`, `models{}`, `capabilities{multilingual,
agents[], evidence_chain, risk_model}`, `limits{max_upload_mb, max_email_bytes,
max_image_pixels, max_urls_per_investigation, network_timeout_seconds}`,
`network{allow_network, page_fetch_enabled}`,
`threat_intelligence{google_safe_browsing, virustotal, urlscan, abuseipdb,
phishtank, urlhaus, rdap}` (each `true/false`).

---

## 5. `POST /api/v1/messages/analyze`

`Content-Type: application/json`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `text` | string (1–20000) | ✅ | message body |
| `language` | `auto\|en\|hi\|bn\|hinglish` | — (default `auto`) | forced language skips detection |
| `channel` | `sms\|whatsapp\|chat\|email\|other` | — (`sms`) | recorded as context |
| `sender` | string ≤200 | — | phone/handle shown to the analyst |
| `metadata` | object | — | non-sensitive context |

```bash
curl -s localhost:8000/api/v1/messages/analyze \
  -H "Content-Type: application/json" \
  -d '{"text":"URGENT: Your SBI account is blocked. Verify KYC now at http://sbi-kyc-verify.xyz/login and pay Rs 499. Share OTP.",
       "language":"en","channel":"sms","sender":"+919999999999"}'
```
Rejects `422` when `text` is empty/over-long or `language` is unknown.

---

## 6. `POST /api/v1/qr/analyze`

`multipart/form-data`

| Part | Type | Required | Notes |
| --- | --- | --- | --- |
| `image` | file | ✅ | PNG/JPEG/WebP; ≤ `MAX_UPLOAD_MB`; ≤ `MAX_IMAGE_PIXELS` |
| `caption` | string | — | visible text/claim around the QR |
| `language` | string | — (`auto`) | `auto\|en\|hi\|bn\|hinglish` |

```bash
curl -s localhost:8000/api/v1/qr/analyze \
  -F image=@samples/qrcode.png \
  -F "caption=Scan this QR to receive your refund" -F language=en
```
`422` for unreadable/invalid images, `413` for oversize.

---

## 7. `POST /api/v1/visual/analyze`

`multipart/form-data`

| Part | Type | Required | Notes |
| --- | --- | --- | --- |
| `image` | file | ✅ | website screenshot |
| `brand_hint` | string | — | brand the page claims (e.g. `State Bank of India`) |
| `claimed_url` | string | — | URL shown/supplied; queued for URL investigation |
| `language` | string | — (`auto`) | |

```bash
curl -s localhost:8000/api/v1/visual/analyze \
  -F image=@samples/screenshot_login.png \
  -F "brand_hint=State Bank of India" \
  -F "claimed_url=https://sbi-secure-login.xyz/login"
```

---

## 8. `POST /api/v1/email/analyze`

`multipart/form-data`

| Part | Type | Required | Notes |
| --- | --- | --- | --- |
| `eml` | file | ✅ | raw RFC 822 / `.eml` |
| `language` | string | — (`auto`) | |

Limit: `min(MAX_EMAIL_BYTES, MAX_UPLOAD_MB × 1 MiB)`.
The first 64 KiB must contain `from:` or `subject:` — otherwise `422`
("does not look like an RFC 822 / .eml message").

```bash
curl -s localhost:8000/api/v1/email/analyze -F eml=@samples/bec_email.eml
```

---

## 9. Report retrieval & verification

### `GET /api/v1/investigations?limit=20&module=message`
`limit` ∈ 1–200. `module` ∈ `message|qr|visual|email` (else `422`).
Returns `ReportSummary[]`: `id, module, created_at, verdict, severity,
risk_score, input_summary` — **no evidence, no raw input**.

```jsonc
[{"id":"inv_638b...","module":"message","created_at":"...",
  "verdict":"malicious","severity":"critical","risk_score":100,
  "input_summary":"SMS from +919999999999: URGENT: ..."}]
```

### `GET /api/v1/investigations/{id}`
Full `InvestigationReport`. `404` if evicted/unknown.

### `GET /api/v1/investigations/{id}/markdown`
`text/markdown; charset=utf-8` with
`Content-Disposition: inline; filename="{id}.md"`.
`404` if unknown.

### `POST /api/v1/investigations/{id}/verify`
Independently recomputes the HMAC-SHA256 hash chain over the stored evidence:

```json
{"investigation_id":"inv_...","valid":true,"errors":[],
 "evidence_count":8,"evidence_fingerprint":"65c688ad..."}
```
`valid=false` with `errors[]` naming the exact item/index that fails
(`sha256 mismatch`, `prev_hash mismatch`, `invalid HMAC chain hash`) when the
ledger has been modified or reordered.

> Verification re-derives `chain_hash` with `EVIDENCE_SIGNING_KEY`. Keep that
> key stable, otherwise previously stored reports cannot be verified after a
> restart or across replicas.

---

## 10. Rate/size limits to know

| Setting | Default | Effect |
| --- | --- | --- |
| `MAX_UPLOAD_MB` | 12 | all uploads |
| `MAX_IMAGE_PIXELS` | 40,000,000 | QR/screenshot decode guard |
| `MAX_EMAIL_BYTES` | 8 MiB | EML parse guard |
| `MAX_URLS_PER_INVESTIGATION` | 6 | URL agent work cap |
| `MAX_REDIRECTS` / `NETWORK_TIMEOUT_SECONDS` | 4 / 8 | untrusted fetch caps |
| `LLM_TIMEOUT_SECONDS` | 90 | per model call |
| `REPORT_CACHE_SIZE` | 500 | in-memory reports (LRU eviction → later `404`) |

---

## 11. Complete smoke test

```bash
python scripts/generate_samples.py

# message → capture investigation_id
ID=$(curl -s localhost:8000/api/v1/messages/analyze \
  -H "Content-Type: application/json" \
  -d @samples/message_sms.json | python -c "import sys,json;print(json.load(sys.stdin)['investigation_id'])")

curl -s localhost:8000/api/v1/investigations | head -c 400
curl -s localhost:8000/api/v1/investigations/$ID | python -m json.tool | head -40
curl -s localhost:8000/api/v1/investigations/$ID/markdown | head -30
curl -s -X POST localhost:8000/api/v1/investigations/$ID/verify

curl -s localhost:8000/api/v1/qr/analyze      -F image=@samples/qrcode.png \
  -F caption="Scan to receive your refund"
curl -s localhost:8000/api/v1/visual/analyze  -F image=@samples/screenshot_login.png \
  -F brand_hint="State Bank of India" -F claimed_url=https://sbi-secure-login.xyz/login
curl -s localhost:8000/api/v1/email/analyze   -F eml=@samples/bec_email.eml
```
