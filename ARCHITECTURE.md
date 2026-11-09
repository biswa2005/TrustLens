# ThreatLens Architecture

> Evidence-first multi-agent investigation platform: **FastAPI** (interface) →
> **LangGraph workflow** (agent orchestration) → **shared forensic engine**
> (tools, network, cryptography, scoring) → **structured report**.

---

## 1. High-level architecture

```
                         ┌──────────────────────────────────────────────┐
   HTTP client ────────► │  FastAPI  (app/main.py)                      │
   curl / SDK / UI       │  routers: messages · qr · visual · email     │
                         │          investigations · health · meta      │
                         └───────────────┬──────────────────────────────┘
                                         │ module service (app/modules/*)
                                         │ validates → builds payload + artifacts
                                         ▼
                         ┌──────────────────────────────────────────────┐
                         │  run_investigation()  (app/agents/graph.py)  │
                         │  isolated per request:                       │
                         │   • AgentRuntime  (settings, llm, services)  │
                         │   • EvidenceStore (HMAC hash chain)          │
                         │   • Toolbox       (16 forensic tools)        │
                         │   • ReportBuilder + ReportStore              │
                         │                                              │
                         │   LangGraph StateGraph  blackboard state     │
                         │   ┌────────────┐   ┌────────────────────┐    │
                         │   │orchestrator│──►│ message│qr│visual│email │
                         │   └────────────┘   └──────────┬─────────┘    │
                         │            ┌──────────────────┼──────┐       │
                         │            ▼                  ▼      ▼       │
                         │        ┌─────┐          ┌──────────┐        │
                         │        │ url │ ───────► │ evidence │        │
                         │        └─────┘  rework  └────┬─────┘        │
                         │            ▲                 ▼              │
                         │            └──────────  ┌────────┐          │
                         │                          │ report │ ──► END │
                         └──────────────────────────┴────────┴──────────┘
                                         │
                                         ▼
      InvestigationReport (findings ⊆ evidence, risk factors, IOCs,
      agent trace, markdown, chain validity) ──► ReportStore ──► GET /investigations
```

### Layer responsibilities

| Layer | Package | Responsibility | Knows about |
| --- | --- | --- | --- |
| Interface | `app/api`, `app/modules` | HTTP validation, upload limits, envelope shaping | schemas, `run_investigation` |
| Orchestration | `app/agents` | Planning, tool selection, collaboration, verification, reporting | engine (read-only), state |
| Forensics engine | `app/engine` | Text/URL/QR/image/email analysis, DNS/TLS/RDAP, threat intel, LLM, evidence, risk | settings, schemas |
| Foundation | `app/config.py`, `app/schemas.py`, `app/services.py` | Configuration, shared models, dependency composition | nothing above |

**Dependency rule:** arrows point downward only. `engine` never imports from
`agents` or `modules`; `agents` never imports FastAPI.

---

## 2. Folder structure (annotated)

```
app/
├── config.py                  # Settings: env-driven, defaults safe, HF optional
├── schemas.py                 # Evidence / Signal / Finding / RiskAssessment /
│                              #   InvestigationReport / IOC / AgentTraceEntry
├── services.py                # ForensicServices composition root (one per app)
│                              #   llm, http, dns, tls, rdap, intel, brands,
│                              #   urls, reports, cache
├── main.py                    # create_app(settings, services) factory + lifespan
│
├── api/
│   ├── deps.py                # get_services(request) dependency
│   ├── health.py              # GET /health, GET /meta
│   ├── investigations.py      # list/get/markdown/verify stored reports
│   └── router.py              # aggregates all routers under API_PREFIX
│
├── modules/
│   ├── common.py              # read_upload, validate_image, execute, envelope,
│   │                          #   safe_language — shared by all four modules
│   ├── message/  schemas.py · service.py · router.py
│   ├── qr/       service.py · router.py
│   ├── visual/   service.py · router.py
│   └── email/    service.py · router.py
│
├── agents/
│   ├── graph.py               # StateGraph wiring, routing predicates,
│   │                          #   run_investigation() entry point
│   ├── state.py               # TypedDict blackboard + _merge_lists reducers
│   ├── runtime.py             # per-investigation handle: llm, store, toolbox,
│   │                          #   evidence_ids(), evidence_digest()
│   ├── types.py               # ToolSpec / ToolResult
│   ├── base.py                # BaseAgent: plan_tools → call → reason → findings
│   ├── prompts.py             # AGENT_PROMPTS, COMMON_RULES, FINDING_CONTRACT
│   ├── toolbox.py             # 16 tools; every tool writes evidence immediately
│   ├── orchestrator.py        # Master Investigation Orchestrator
│   ├── message_agent.py       # multilingual text findings
│   ├── qr_agent.py            # QR/UPI findings
│   ├── visual_agent.py        # VLM/OCR impersonation findings
│   ├── email_agent.py         # auth, BEC, identity, attachment findings
│   ├── url_agent.py           # infrastructure + lookalike findings
│   ├── evidence_agent.py      # chain verification, finding gating, URL rework
│   └── report_agent.py        # risk, explainer, report build + store
│
├── engine/
│   ├── utils.py               # ids, sha256, HMAC chain, truncation, dedupe
│   ├── cache.py               # TTLCache (DNS/TLS/RDAP/intel memoisation)
│   ├── hf.py                  # Hugging Face router HTTP adapter, LLMUnavailable
│   ├── llm.py                 # LLMService: chat, json_chat, model_info, offline
│   ├── net.py                 # SafeHttpClient (SSRF guard, API vs untrusted)
│   ├── brands.py + data/brands.json  # official domains, typosquat/homoglyph match
│   ├── urls.py                # normalize/extract, static signals, UPI, entities
│   ├── url_investigator.py    # static+DNS+TLS+RDAP+intel+fetch → reputation
│   ├── dns_ssl.py             # DNSAnalyzer, TLSAnalyzer, RDAPAnalyzer
│   ├── threat_intel.py        # GSB / VT / urlscan / AbuseIPDB / URLHaus / PhishTank
│   ├── web.py                 # safe page fetch: redirect chain, forms, brand hints
│   ├── text_signals.py        # EN/HI/BN/Hinglish rules (transparent expert system)
│   ├── qr_utils.py            # cv2 QR decode + payload classification
│   ├── image_utils.py         # PIL validation, sha256, basic image evidence
│   ├── email_utils.py         # EML parse: headers, bodies, attachments, flags
│   ├── email_auth.py          # SPF/DKIM/DMARC independent verification
│   ├── evidence.py            # EvidenceStore + verify_evidence_chain()
│   ├── risk.py                # additive category-capped RiskEngine
│   ├── explain.py             # Explainer: grounded narrative (LLM or template)
│   └── report.py              # ReportBuilder, ReportStore, Markdown renderer
```

---

## 3. Request lifecycle (one investigation)

1. **HTTP boundary.** The module router validates the request (Pydantic body or
   multipart upload + `read_upload` size cap + `validate_image` pixel cap).
2. **Service call.** `app/modules/<mod>/service.py` builds a `payload`
   (serialisable, safe to show in reports) and `artifacts`
   (`image_bytes` / `eml_bytes` / hints), then calls `execute()`.
3. **Runtime creation.** `run_investigation()` makes **an isolated**
   `EvidenceStore`, `Toolbox`, and `AgentRuntime` for this request — no state
   leaks between investigations.
4. **Graph execution.** LangGraph `ainvoke` walks the conditional workflow
   (section 4). Nodes return *partial* state; reducers merge list keys,
   scalar keys are last-write-wins.
5. **Evidence writing.** Tools write to the `EvidenceStore` **immediately**
   when executed. Evidence items are append-only and hash-linked
   (section 6). Agents never re-add tool-produced evidence.
6. **Verification gate.** The evidence agent re-verifies the chain, drops
   ungrounded findings, downgrades unsupported severe findings, and queues at
   most **2** URL rework passes for links found in the input but never studied.
7. **Report.** The report agent recomputes risk (transparency), asks the
   explainer for a narrative grounded in the evidence digest, renders Markdown,
   and stores the report.
8. **Response.** The module returns `ReportEnvelope{investigation_id, module,
   report}`; the report is retrievable via `/investigations/{id}` until the LRU
   evicts it.

**Failure path:** if the graph raises, `run_investigation` still calls the
report agent over the partial state so collected evidence is not lost; the
result carries `status: failed` and `error`, and the API maps "no report" to
HTTP 500 with that error.

---

## 4. LangGraph workflow

`InvestigationState` is a `TypedDict`. List keys (`findings`, `signals`, `iocs`,
`trace`, `visited`, `agent_summaries`) use `_merge_lists` reducers — that is why
a node may return only *its* additions. Scalar keys (`pending_urls`,
`pending_domains`, `requested_agents` are lists too and therefore
**last-write-wins**: returning `[]` clears the queue — by design, it means
"no more work for you").

```
START ──► orchestrator
             │  _route_after_orchestrator
             ├──► message │ qr │ visual │ email   (primary specialist)
             ├──► url       (if work queued)
             ├──► evidence  (if already visited)
             └──► report
   specialist ──► _route_after_specialist ──► url (if pending_urls/pending_domains
                                             or "url" requested) │ evidence
   url ──► evidence
   evidence ──► _route_after_evidence ──► url   (bounded rework, ≤2)
                                    ├─► a never-visited requested specialist
                                    └─► report
   report ──► END
```

`recursion_limit` is capped (`max_steps=40`) so a malformed input cannot loop
the graph forever.

### What each node contributes

| Node | Writes to state | Reads from state |
| --- | --- | --- |
| `orchestrator` | `plan`, `trace`, `visited`, clears `requested_agents` | `module`, `language`, `input` |
| specialist (message/qr/visual/email) | `findings`, `signals`, `iocs`, `trace`, `visited`, `agent_summaries`, `pending_urls`, `entities` | `input`, `artifacts`, `plan` |
| `url` | infrastructure/lookalike findings, DNS/TLS/RDAP/intel evidence, `visited` | `pending_urls`, `pending_domains` |
| `evidence` | `verification`, `evidence_chain_valid`, `requested_agents`, `pending_urls`, `rework_count`, `trace` | `findings`, whole evidence store |
| `report` | `report`, `status`, final `trace` | everything |

---

## 5. Shared investigation engine

### 5.1 Hugging Face integration (`hf.py`, `llm.py`)

- OpenAI-compatible router `https://router.huggingface.co/v1` over `httpx`.
- Default models: `Qwen/Qwen2.5-72B-Instruct` (text),
  `Qwen/Qwen2.5-VL-72B-Instruct` (vision), `Qwen/Qwen2.5-7B-Instruct` (fast).
- `LLMService.json_chat()` requests JSON, extracts/repairs it once, then fails
  closed to `LLMUnavailable`, which the calling agent converts into an
  honest `warning` trace entry instead of a crash.
- `reasoning_mode` is either `huggingface` or `offline-expert-system`;
  `degraded` is `true` whenever a model call did not actually produce the text.
- **Offline mode is a real expert system, not a stub:** rule engines for text,
  URLs, UPI, QR, email and risk still run, and the report says so.

### 5.2 URL/domain intelligence (`urls.py`, `brands.py`, `url_investigator.py`)

* **Static analysis** — normalization, scheme/port/path/query, punycode decode,
  IP-literal, shortener, brand registry match (official / brand-in-subdomain /
  homoglyph / typosquat / keyword-combo), lure words, URL length, entropy-ish
  token checks, download/executable path, per-signal weight + category.
* **DNS** — A/AAAA/MX/NS/TXT/CNAME, SPF and DMARC records parsed from TXT.
* **TLS** — certificate issuer/subject/validity/SAN/expiry, chain verified
  (with a separate unverified probe recorded when verification fails).
* **RDAP** — creation date → domain age (a fresh domain is a strong signal).
* **Threat intel** — pluggable correlator; each provider returns
  `clean|suspicious|malicious|unknown|not_configured|error` and is reported
  individually (never collapsed into "safe").
* **Safe page fetch** — `SafeHttpClient.fetch_untrusted`: resolve → require a
  **global** IP (SSRF guard), cap redirects/time/bytes, record the redirect
  chain, harvest forms/title/text hints. Disabled with `ENABLE_PAGE_FETCH=false`.
* **Reputation** — additive score with category caps → verdict.

### 5.3 Evidence ledger (`evidence.py`)

```python
chain_hash = HMAC_SHA256(key, prev_hash, stable_json(digest_payload(item)))
digest = {id, kind, source, summary, data, confidence, collected_at}
```

* Append-only; each item stores `sha256`, `prev_hash`, `chain_hash`.
* `verify_evidence_chain(items, key)` recomputes everything and returns
  `(valid, errors)` — used by the evidence agent *and* by
  `POST /investigations/{id}/verify` after the fact.
* Tampering with a summary, reordering items, or appending a forged item all
  break the chain (covered by tests).

### 5.4 Risk assessment (`risk.py`)

```
score = Σ_capped(category contributions) + bounded combination bonuses
```

* Categories: identity, payment, pressure, link, threat_intel, auth, visual,
  content, obfuscation, infrastructure — **each capped** (e.g. identity = 30),
  so ten weak identity signals can never swamp the score.
* Combination bonuses (e.g. identity + credential-lure) are themselves capped.
* Output: `RiskAssessment{score, severity, verdict, confidence, factors[],
  category_scores{}, summary, confidence_basis, evidence_coverage}`.
* Factors carry the reason and the evidence IDs → the report can show exactly
  *why* the number is what it is.
* This is a **rule engine, not a model**; it is deterministic and unit-tested.

### 5.5 AI explanation (`explain.py`)

`Explainer.explain(...)` receives the risk object, the findings, a *digest of
the evidence* and module context. With a model available it asks for a
grounded narrative and records `narrative_source: huggingface`; otherwise it
renders a deterministic template and records
`narrative_source: deterministic-template`. Either way the report states which
one produced the text.

### 5.6 Report building (`report.py`)

`ReportBuilder.build(...)` assembles `InvestigationReport` (findings, evidence,
IOCs, recommendations, plan, agent trace, model info, metadata, chain validity)
and `render_markdown()` produces the human-readable document with sections:
summary → risk → findings → recommendations → IOCs → evidence ledger → agent
trace → limitations. `ReportStore.add/get/list` is an in-memory LRU
(`REPORT_CACHE_SIZE`); replace it to persist.

---

## 6. Cross-cutting concerns

| Concern | Implementation |
| --- | --- |
| Tamper evidence | HMAC-SHA256 hash chain; standalone re-verification endpoint |
| Grounding invariant | `EvidenceVerificationAgent` drops findings with no live evidence IDs |
| SSRF | global-IP enforcement, redirect caps, scheme allowlist, byte/time caps |
| Resource limits | upload MB, image pixels, email bytes, URLs per investigation |
| Multilingual | script detection (Devanagari/Bengali/Latin) + per-language rules incl. Hinglish |
| Honest degradation | `degraded`, `reasoning_mode`, `narrative_source`, `limitations[]` |
| Observability | `agent_trace[]` with tool, status, latency, model per step |
| Concurrency | one `EvidenceStore`/`Toolbox` per investigation; shared caches are keyed |

---

## 7. Scaling-out checklist

1. Replace `ReportStore` with Redis/Postgres (keep `add/get/list`).
2. Move `run_investigation` behind a task queue (Celery/arq) — the function is
   already async and self-contained.
3. Set `EVIDENCE_SIGNING_KEY` from a secret manager so verification survives
   restarts and multiple replicas.
4. Add a per-key rate limiter at the API layer.
5. Persist evidence to object storage for long-term forensics.
