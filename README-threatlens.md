# ThreatLens

**Evidence-first, multi-agent digital-fraud investigation platform.**

ThreatLens takes a suspicious message, QR image, website screenshot or raw email
and runs it through a **LangGraph multi-agent workflow** that collects
*tamper-evident evidence*, reasons about it with **Hugging Face LLMs/VLMs**, and
returns a structured report where **every finding cites the evidence that proves
it**.

| Module | Endpoint | What it investigates |
| --- | --- | --- |
| Message / SMS | `POST /api/v1/messages/analyze` | Multilingual (English, Hindi, Bengali, Hinglish) scam text, psychological manipulation, payment IDs, links |
| QR | `POST /api/v1/qr/analyze` | QR decode, UPI payment semantics, embedded URLs, "you will receive money" contradictions |
| Visual | `POST /api/v1/visual/analyze` | Screenshot brand impersonation, address-bar mismatch, credential-harvesting forms (VLM + OCR) |
| Email | `POST /api/v1/email/analyze` | EML parsing, independent SPF/DKIM/DMARC verification, BEC, invoice/payment-change fraud, static attachment triage |

---

## Key design principles

1. **Evidence first.** Every observation is stored in an HMAC-SHA256
   hash-chained ledger. A finding that references no stored evidence is
   *dropped* by the Evidence Verification agent, and high-severity findings with
   only weak evidence are *downgraded*.
2. **Genuine agentic behaviour.** Eight agents plan, act, verify and report:
   they share a blackboard state, hand work to each other (`pending_urls`,
   `requested_agents`), and can request a bounded rework pass.
3. **Explainability over black boxes.** Risk is an *additive, category-capped
   rule engine*, never a model score. Each factor lists its weight, reason and
   evidence IDs. LLM narratives are generated **from** the evidence digest and
   clearly labelled (`narrative_source`).
4. **No required credentials.** Without `HF_TOKEN` the platform runs in an
   honest **offline expert-system mode** (`degraded: true`,
   `reasoning_mode: offline-expert-system`). It never pretends deterministic
   rules are LLM reasoning.
5. **Safe by construction.** Untrusted URLs are fetched only through an SSRF-
   guarded client (global-address resolution, redirect limits, size/time caps).
   Attachments are never executed; archives are never extracted.

---

## Quick start

```bash
# 1. Python 3.11+ required
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # macOS/Linux
pip install -r requirements.txt
pip install -r requirements-dev.txt   # tests, samples, linting

# 2. Configure (optional — everything works without a token)
copy .env.example .env        # Windows
cp .env.example .env          # macOS/Linux
#    edit .env -> set HF_TOKEN=hf_... for model reasoning
#                  EVIDENCE_SIGNING_KEY=... for cross-restart verification

# 3. Generate demo inputs
python scripts/generate_samples.py

# 4. Run the API
python run.py                 # or: uvicorn app.main:app --reload
# open http://127.0.0.1:8000/docs
```

### First requests

```bash
# Message
curl -s localhost:8000/api/v1/messages/analyze \
  -H "Content-Type: application/json" \
  -d @samples/message_sms.json

# QR
curl -s localhost:8000/api/v1/qr/analyze \
  -F image=@samples/qrcode.png \
  -F caption="Scan to receive your refund"

# Screenshot
curl -s localhost:8000/api/v1/visual/analyze \
  -F image=@samples/screenshot_login.png \
  -F brand_hint="State Bank of India" \
  -F claimed_url=https://sbi-secure-login.xyz/login

# Email
curl -s localhost:8000/api/v1/email/analyze -F eml=@samples/bec_email.eml

# Retrieve, download and re-verify a report
curl -s localhost:8000/api/v1/investigations
curl -s localhost:8000/api/v1/investigations/inv_XXXX
curl -s localhost:8000/api/v1/investigations/inv_XXXX/markdown
curl -s -X POST localhost:8000/api/v1/investigations/inv_XXXX/verify
```

---

## Testing

```bash
.venv\Scripts\python.exe -m pytest          # 22 tests, fully offline
.venv\Scripts\python.exe -m ruff check app tests
```

The suite forces `LLM_MODE=offline`, `ALLOW_NETWORK=false` — no token, no
network, real forensic code paths. It covers the API surface, all four modules,
evidence grounding invariants, tamper/reorder detection on the hash chain, risk
category caps, multilingual detection and brand/homoglyph checks.

---

## Repository layout

```
C:\hack
├── app/
│   ├── config.py            # Settings (env-driven, safe defaults)
│   ├── schemas.py           # Evidence, Signal, Finding, RiskAssessment, reports
│   ├── services.py          # ForensicServices composition root
│   ├── main.py              # FastAPI app factory (create_app)
│   ├── api/                 # health, investigations, deps, aggregate router
│   ├── modules/             # message | qr | visual | email (schema+service+router)
│   ├── agents/              # LangGraph agents, tools, state, prompts
│   │   ├── graph.py         # StateGraph workflow + run_investigation()
│   │   ├── orchestrator.py  # Master Investigation Orchestrator
│   │   ├── base.py          # ReAct loop, grounding, finding merge
│   │   ├── toolbox.py       # 16 forensic tools -> evidence ledger
│   │   ├── message_agent.py qr_agent.py visual_agent.py email_agent.py
│   │   ├── url_agent.py evidence_agent.py report_agent.py
│   │   ├── state.py runtime.py types.py prompts.py
│   ├── engine/              # shared investigation engine (see ARCHITECTURE.md)
│   └── data/brands.json     # brand + homoglyph registry
├── docs/                    # AGENTS.md, API.md, MODULES.md
├── tests/                   # offline test suite
├── scripts/generate_samples.py
├── run.py  .env.example  requirements.txt  requirements-dev.txt
├── pyproject.toml           # ruff + pytest configuration
└── ARCHITECTURE.md  README.md
```

---

## Documentation map

| Document | Contents |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture, folder structure, data flow, engine internals |
| [docs/AGENTS.md](docs/AGENTS.md) | The eight agents, the LangGraph edges, blackboard communication protocol |
| [docs/API.md](docs/API.md) | Every endpoint, request/response schemas, error model, curl examples |
| [docs/MODULES.md](docs/MODULES.md) | Per-module architecture, files, flow, endpoints, agent communication, testing |

---

## Verdict & severity scales

**Verdict:** `benign` (<20) · `suspicious` (20–44) · `likely_malicious` (45–69) ·
`malicious` (≥70) · `inconclusive` (evidence required for the verdict was absent).

**Severity:** `critical` (≥80) · `high` (≥60) · `medium` (≥40) · `low` (≥20) ·
`info`.

A screenshot without any VLM/OCR observation, or a QR image that could not be
decoded, **cannot** return `benign`: the report agent forces `inconclusive` (or
keeps a higher verdict if other probative evidence, such as a lookalike URL,
was collected).

---

## Production notes

- **Report storage** is an in-memory `ReportStore` (LRU). Swap
  `app/engine/report.py::ReportStore` for a database-backed implementation with
  the same `add/get/list` interface.
- Set `EVIDENCE_SIGNING_KEY` before persisting reports you need to verify later.
- Terminate TLS at a reverse proxy; keep `ALLOW_NETWORK` enabled only where
  outbound investigation is permitted.
- Threat-intelligence providers are optional and independently reported
  (`not_configured` ≠ `clean`).
