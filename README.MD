# ThreatLens - Evidence-First Digital-Fraud Investigation Platform

ThreatLens takes a suspicious SMS/WhatsApp message, a QR image, a website
screenshot, or a raw `.eml` file and returns a structured fraud report where
**every finding cites the tamper-evident evidence that proves it**.

## Problem

Scam messages, QR/UPI payment tricks, fake login screenshots and business-email
compromise (BEC) attacks are increasingly multi-channel and multilingual, yet
most detection tools either return a single opaque score or hallucinate reasons
that cannot be audited. Victims and analysts cannot answer "why is this flagged,
and what is the proof?"

## Solution

ThreatLens is a **LangGraph multi-agent pipeline** that collects evidence first
(HMAC-SHA256 hash-chained ledger), reasons with Hugging Face LLMs/VLMs, and
verifies each finding against stored evidence: a finding that cites no evidence
is dropped and high-severity findings without strong evidence are downgraded.
Risk is an additive, category-capped rule engine (never a model score), every
factor lists its weight, reason and evidence IDs, and LLM narratives are
generated from the evidence digest and labelled (`narrative_source`). It runs
fully offline when `HF_TOKEN` is absent (`degraded: true`, `reasoning_mode:
offline-expert-system`), supports English, Hindi, Bengali and Hinglish, and
performs independent SPF/DKIM/DMARC verification, QR/UPI semantics, OCR/VLM
screenshot analysis, and SSRF-guarded network investigation. No required
credentials.

## Demo links and a screenshot

- Live link: not deployed - run locally using the steps below (opens at
  `http://127.0.0.1:8000/docs`, no login required).
- Screenshot: `docs/screenshot.png` (workspace UI / Swagger screenshot).

## Tech stack

- **Backend**: Python 3.12, FastAPI, Uvicorn, Pydantic v2
- **Agent workflow**: LangGraph + LangChain, ReAct loops, blackboard state
- **Models** (optional): Hugging Face Inference - Qwen/Qwen2.5-72B-Instruct
  (text), Qwen/Qwen2.5-7B-Instruct (fast), Qwen/Qwen2.5-VL-72B-Instruct
  (vision), via the OpenAI-compatible router
- **Storage**: in-memory LRU ReportStore (swap-ready), optional PostgreSQL 16 +
  pgvector (URL/cache), Redis 7 (URLhaus indicators)
- **Network / forensics**: SSRF-guarded HTTP client, dnspython, tldextract,
  idna, rapidfuzz, confusable-homoglyphs, selectolax, cryptography, pyOpenSSL,
  certifi
- **Email**: stdlib email parsing, dnspython (DNS), independent SPF/DKIM/DMARC
- **Frontend**: React 19, TypeScript, Vite 8, Tailwind CSS v4 (web/ and frontend/)
- **Quality**: pytest, ruff, hypothesis, httpx; offline test suite (22+ tests)

## Architecture

    client
      -> FastAPI (app/main.py, /api/v1/*)
           -> Master Investigation Orchestrator (LangGraph StateGraph)
                -> Module agents: message | qr | visual | email
                     -> URL investigator / forensic toolbox (16 tools)
                          -> evidence ledger (HMAC-SHA256 hash chain)
                -> URL agent, Evidence Verification agent, Report agent
           -> Report store (JSON + Markdown) + chain verify endpoint

- `app/agents/` - eight LangGraph agents, tools, state, prompts
- `app/modules/` - message, qr, visual, email (schema + service + router)
- `app/engine/` - LLM (auto/offline), safe HTTP, DNS/RDAP/TLS, threat intel,
  report store, evidence chain, brands
- `src/links/` - standalone URL threat analysis (Module 1/2, TLS cert trust,
  redirects, reputation integrations)
- `web/`, `frontend/` - React UIs

Every finding carries `evidence_ids` pointing into the ledger; tampering or
reordering of evidence breaks the chain and is reported as invalid.

## Setup and run steps

Requires Python 3.12+. No paid keys are required for the core demo.

```bash
# 1. Clone and enter the project
git clone https://github.com/<owner>/TrustLens.git
cd TrustLens

# 2. Create and activate a venv
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt   # tests (optional)

# 4. Configure environment (optional; works without tokens)
copy .env.example .env           # Windows
# cp .env.example .env          # macOS / Linux
# Edit .env to set HF_TOKEN=hf_... for model reasoning (recommended for demo)
# and EVIDENCE_SIGNING_KEY=... to keep reports verifiable across restarts.

# 5. Generate sample inputs used by the demo
python scripts/generate_samples.py

# 6. Run the API
python run.py
# or: uvicorn app.main:app --reload
# Open http://127.0.0.1:8000/docs
```

### Optional supporting services (Module 1/2 URL deep-dive)

```bash
docker compose up --build -d     # PostgreSQL 16 + pgvector, Redis 7, fetcher
```
Host ports default to `55432` (Postgres) and `6379` (Redis); set `DATABASE_URL`,
`TEST_DATABASE_URL` and `REDIS_URL` in `.env` accordingly. Import the URLhaus
feed once on the host: `python scripts/import_urlhaus.py`.

### Frontend

```bash
cd web        # or frontend/
npm install
npm run dev
```

### First requests

```bash
curl -s localhost:8000/api/v1/messages/analyze \
  -H "Content-Type: application/json" \
  -d @samples/message_sms.json

curl -s localhost:8000/api/v1/qr/analyze \
  -F image=@samples/qrcode.png \
  -F caption="Scan to receive your refund"

curl -s localhost:8000/api/v1/visual/analyze \
  -F image=@samples/screenshot_login.png \
  -F brand_hint="State Bank of India" \
  -F claimed_url=https://sbi-secure-login.xyz/login

curl -s localhost:8000/api/v1/email/analyze -F eml=@samples/bec_email.eml

# Retrieve / download / re-verify a report
curl -s localhost:8000/api/v1/investigations
curl -s localhost:8000/api/v1/investigations/inv_XXXX
curl -s localhost:8000/api/v1/investigations/inv_XXXX/markdown
curl -s -X POST localhost:8000/api/v1/investigations/inv_XXXX/verify
```

### Tests

```bash
.venv\Scripts\python.exe -m pytest          # fully offline; 22+ tests
.venv\Scripts\python.exe -m ruff check app tests
```

## Disclosures (libraries, templates, AI tools)

- Templates: started from a FastAPI scaffold (MIT-style boilerplate), React +
  Vite + Tailwind scaffold for the UIs.
- Libraries listed above (see Tech stack); chain libraries `dnspython`,
  `tldextract`, `cryptography`, `pyOpenSSL`, `confusable-homoglyphs`, `rapidfuzz`,
  `selectolax`.
- AI tools: Hugging Face inference providers (Qwen models, optional via
  `HF_TOKEN`); AI coding assistance used during development (Claude), with final
  code reviewed by the author. No generated content is presented as verified
  without evidence grounding.
- No sample contains real personal data; samples are synthetically generated by
  `scripts/generate_samples.py`.

## Track

AI / Trust and Safety - digital-fraud and phishing investigation.

## Demo video

Link: <add after recording>
Format: short link that opens without a login, maximum 3 minutes. Shows the app
working (not slides) on real sample data, opened with the problem statement in
one or two sentences.

- Open with the problem, then demonstrate all four modules and the verify endpoint.
- Show evidence citations and the hash-chain verification (`valid: true`).
- Clear audio. Link must open without a login.
- Required paid keys or special hardware: none for the default offline demo;
  set `HF_TOKEN` for LLM reasoning (shown live in the video).
