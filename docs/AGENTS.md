# Agents & Collaboration

ThreatLens runs **eight agents** in a LangGraph `StateGraph`. They communicate
exclusively through a shared **blackboard state** plus an **external evidence
store** — no agent calls another agent directly. That keeps the workflow
auditable: every hand-off is a state transition you can read back from the
report's `agent_trace`.

---

## 1. The eight agents

| # | Node | Agent class | File | Role |
| --- | --- | --- | --- | --- |
| 1 | `orchestrator` | `OrchestratorAgent` | `app/agents/orchestrator.py` | **Master Investigation Orchestrator** — decides the plan: primary specialist, focus questions, depth, whether URL work is needed |
| 2 | `message` | `MessageInvestigationAgent` | `message_agent.py` | Multilingual scam/manipulation analysis, entities, links & payment IDs for hand-off |
| 3 | `qr` | `QRInvestigationAgent` | `qr_agent.py` | QR decode, payload classification, UPI semantics, embedded URL extraction |
| 4 | `visual` | `VisualWebsiteAgent` | `visual_agent.py` | VLM description + OCR of a screenshot, brand impersonation, credential-form and address-bar checks |
| 5 | `email` | `EmailForensicsAgent` | `email_agent.py` | EML headers/identity, SPF/DKIM/DMARC, BEC, attachments, HTML deception, body analysis |
| 6 | `url` | `URLIntelligenceAgent` | `url_agent.py` | **URL Intelligence** — infrastructure study of every queued URL/domain (static, DNS, TLS, RDAP, threat intel, safe fetch) |
| 7 | `evidence` | `EvidenceVerificationAgent` | `evidence_agent.py` | **Evidence Verification** — chain integrity, finding grounding, severity gating, missing-URL rework requests |
| 8 | `report` | `FinalReportAgent` | `report_agent.py` | **Final Report Generation** — filtered findings, risk assessment, explainer narrative, Markdown, store |

Specialist agents (2–5) subclass `BaseAgent` (`base.py`) and share one ReAct
loop. Agents 1, 7 and 8 are orchestration roles with their own `run()`.

---

## 2. Communication protocol (the blackboard)

### State keys

| Key | Merge rule | Meaning |
| --- | --- | --- |
| `findings` | append (list reducer) | `Finding` objects; **each must cite `evidence_ids`** |
| `signals` | append | weighted `Signal` indicators feeding the risk engine |
| `iocs` | append | extracted indicators of compromise (URLs, VPA, phone…) |
| `trace` | append | `AgentTraceEntry` — the audit log rendered in the report |
| `visited` | append | agents that ran (used by routing/completeness) |
| `agent_summaries` | append | `{agent, summary, findings, evidence_collected}` |
| `entities` | last-write-wins | sender/brand/subject/etc. |
| `pending_urls`, `pending_domains` | **scalar list = last-write-wins** | work queue for the URL agent |
| `requested_agents` | **scalar list** | the evidence agent's rework requests |
| `rework_count` | scalar | bounded rework budget (≤2) |
| `verification` | scalar dict | dropped findings, severity updates, chain state |
| `plan`, `status`, `error`, `report` | scalar | plan / outcome |

> ⚠️ Because list-valued keys are last-write-wins, a specialist that has no new
> URLs must return `[]` to *clear* the queue after consuming it — this is the
> protocol that prevents the URL agent from re-processing the same links.

### Hand-off patterns actually used

1. **Queue (specialist → URL).** The message agent returns
   `pending_urls=[...]` extracted from the text; the QR agent queues decoded
   destinations; the visual agent queues the *observed* and *claimed* URLs; the
   email agent queues body links. The router then sends control to `url`.
2. **Request (evidence → specialist/URL).** `requested_agents=["url"]` plus a
   fresh `pending_urls` list asks for one more pass; guarded by `rework_count`.
3. **Verification verdict (evidence → report).** The evidence agent writes a
   `verification` dict: `dropped_finding_ids`, `finding_updates` (severity
   changes), `chain_valid`, `missing_urls`, and human-readable `notes`. The
   report agent applies it before scoring.
4. **Findings through evidence IDs.** Agents never pass raw tool output to each
   other — they pass `Finding.evidence_ids`, and the receiving agent can open
   the same item in `runtime.store`.
5. **Shared summary.** Each node appends an `agent_summaries` entry so the final
   report can narrate what every agent did.

### Runtime handle

Everything an agent needs arrives via `AgentRuntime` (`runtime.py`):

```python
runtime.settings     # configuration
runtime.llm          # LLMService (chat/json_chat/model_info/mark_degraded)
runtime.services     # ForensicServices: dns, tls, rdap, intel, urls, brands, reports
runtime.toolbox      # 16 forensic tools (per-investigation artifact cache)
runtime.store        # EvidenceStore (append-only HMAC chain)
runtime.evidence_ids()      # set of valid evidence IDs for grounding checks
runtime.evidence_digest()   # compact, LLM-safe digest of collected evidence
runtime.investigation_id / module / language / report_builder
```

---

## 3. The specialist ReAct loop (`base.py`)

Every specialist `run()` executes:

```
plan_tools(state, runtime)            # deterministic, input-aware tool plan
   │  (email: parse_email BEFORE verify_email_auth — artifact dependency;
   │   url: only URLs/domains not already investigated in this run)
   ▼
for each tool:  runtime.toolbox.call(name, args)
   │  • tool writes evidence into runtime.store immediately
   │  • failure is recorded as an `error` trace entry, never fatal
   ▼
if runtime.llm.available:
      _reason(...)   # model reasoning over tool output, strictly schema'd
      else trace status = "skipped"  (honest: no model, no invented reasoning)
   ▼
deterministic_findings(...)           # evidence-cited findings derived from tools
   + self.finding(...) helper (IDs, truncation, confidence clamping)
   ▼
return partial state (findings/signals/iocs/trace/pending_urls/...)
```

**Grounding contract** (`prompts.py::FINDING_CONTRACT`): a finding must
reference real evidence IDs, quote short excerpts, state uncertainty, and never
claim work that was not performed.

---

## 4. Tooling (`toolbox.py`) — 16 tools

| Tool | Used by | Produces (evidence kinds) |
| --- | --- | --- |
| `analyze_message` | message, email(body) | `message_signal`, `message_text` |
| `extract_urls` | message, qr, visual, email | `url_reference`, `entity` |
| `decode_qr` | qr | `qr_image`, `qr_payload` |
| `parse_upi` | qr | `upi_uri` |
| `analyze_qr_context` | qr | caption/claim contradictions → signals |
| `analyze_screenshot` | visual | `image`, `vlm_observation` (or `ocr_text` fallback) |
| `local_ocr` | visual | `ocr_text` |
| `compare_brand_reference` | visual | `image_similarity` + brand checks |
| `parse_email` | email | `email_headers`, `email_body`, `email_attachment`, `email_hop` |
| `verify_email_auth` | email | `email_auth` (independent SPF/DKIM/DMARC or explicit `not_verified`) |
| `investigate_url` | url | `url_static`, `dns`, `ssl`, `rdap`, `threat_intel`, `url_fetch` |
| `investigate_domain` | url | `dns`, `rdap`, `url_static` (domain-only) |
| `dns_lookup` / `tls_inspect` / `rdap_lookup` / `threat_intel_lookup` | url (fine-grained) | matching kinds |
| `analyze_qr_context`, `parse_upi` | qr | UPI warnings such as the "receive money" contradiction |

Tool results are `ToolResult{name, summary, evidence, signals, iocs, data,
pending_urls, pending_domains, notes}`. **Evidence inside a `ToolResult` is
already stored** — the base agent must not add it again.

---

## 5. Graph wiring (`graph.py`)

```python
graph = StateGraph(InvestigationState)
graph.add_node("orchestrator", run_orchestrator)
for name, agent in specialists.items(): graph.add_node(name, run_specialist)
graph.add_node("url", run_url); graph.add_node("evidence", run_evidence); graph.add_node("report", run_report)

graph.add_edge(START, "orchestrator")
graph.add_conditional_edges("orchestrator", _route_after_orchestrator, {...})
for name in SPECIALISTS: graph.add_conditional_edges(name, _route_after_specialist, {"url":…, "evidence":…})
graph.add_edge("url", "evidence")
graph.add_conditional_edges("evidence", _route_after_evidence, {..., "report": "report"})
graph.add_edge("report", END)
```

Routing predicates (all pure functions of state):

* `_route_after_orchestrator` — the primary specialist first; then URL work;
  then evidence; then report.
* `_route_after_specialist` — `url` if work is queued or requested, else
  `evidence`.
* `_route_after_evidence` — honour rework requests while
  `rework_count <= 2` and work remains; never re-visit a visited specialist;
  otherwise `report`.

---

## 6. What each agent decides

### Master Investigation Orchestrator
Builds `plan{primary, agents, rationale, focus[], depth, mode}`. With a model it
asks for JSON (`llm-planner`) and *sanitises* the answer: only known agents,
primary forced first, `evidence`/`report` always present, `url` appended if
links exist. Without a model it uses a deterministic plan
(`mode: offline-planner`). A **guardrail** scans the input text and appends URL
work whenever links are visibly present.

### Message agent
Runs `analyze_message` (script/language detection → per-language rules →
manipulation tactics with quotes → scam-type confidences) plus URL extraction.
Produces phishing/KYC/OTP/job/loan/extortion findings, a manipulation finding
quoting the wording, entity/IOC extraction, and queues every link.

### QR agent
Decodes the image (OpenCV, multi-scale, fallback decode), stores the payload
and image hash, classifies the payload (UPI / URL / text / Wi-Fi / vCard),
parses UPI semantics (`pa`, `pn`, `am`, `tn`, known-handle checks, the
"receive/refund" lie), cross-checks the visible caption for contradictory
claims, and queues embedded URLs.

### Visual agent
Runs the vision model (VLM) with brand hint + claimed URL, otherwise local OCR,
otherwise **records that visual analysis was impossible** (never a false
"clean"). Findings cover brand impersonation, login/password fields, address-bar
disagreement, HTTPS absent, lookalike domain vs. official registry, and visual
inconsistencies — then queues observed/claimed URLs.

### Email agent
Tool order matters: `parse_email` first (artifact cache), then
`verify_email_auth`. Findings groups: **authentication** (live failures are
critical; header claims that contradict live results are critical; when offline,
claims are explicitly labelled *unverified*), **identity** (Reply-To/Return-Path/
Sender/Message-ID mismatches, punycode, display-brand vs. free-mail domain),
**BEC** (payment-change + executive impersonation + fake thread), **attachments**
(executable/macro/DDE/double-extension → high; invoice theme → medium; never
executed, archives never extracted), **HTML** (password forms, link-text
mismatch, hidden text) and **body** (the multilingual engine run over the body).

### URL Intelligence agent
Plans one `investigate_url` per *un-investigated* queued URL (capped by
`MAX_URLS_PER_INVESTIGATION`) plus `investigate_domain` only for domains no URL
already covers. Findings: malicious/high-risk/suspicious/no-adverse
infrastructure (each stating the score and its components), dedicated
**brand-lookalike**, **threat-intel match**, and **direct download** findings —
always noting that "no blocklist hit ≠ safe".

### Evidence Verification agent
1. Re-runs `store.verify()` (HMAC chain).
2. Drops findings citing unknown evidence; strips unknown IDs.
3. Downgrades `high+` findings that have **no** verified/high-confidence
   evidence by one level.
4. Compares input-extracted URLs against `url_static` evidence → queues a
   bounded rework (`requested_agents=["url"]`, ≤2 passes).
5. Writes one `verification` evidence item and the `verification` state dict.

### Final Report agent
Applies verification updates → de-duplicates IOCs → computes plan completeness →
runs `RiskEngine` (with a **guardrail**: visual/QR without their core evidence
cannot return `benign`) → asks the explainer for a grounded narrative → builds
and stores the report → appends its own trace entry → sets `status=completed`.

---

## 7. Agent communication example (screenshot with a claimed URL)

```
orchestrator  plan: primary=visual, agents=[visual, url, evidence, report]
visual        evidence: image + VLM/OCR observation
              state: pending_urls=["https://sbi-secure-login.xyz/login"]
url           evidence: url_static, dns, ssl, rdap, threat_intel
              findings: "Lookalike domain targets a brand", "Suspicious infrastructure"
evidence      chain valid; findings kept; requested_agents=[] (all links covered)
report        risk=…, narrative_source=…, status=completed
```

If the vision model were unavailable: `visual` records an explicit
"could not be visually analysed" INFO finding, and `report` forces
`verdict=inconclusive` when no other probative evidence lifted the score ≥20.

---

## 8. Testing agents

```bash
.venv\Scripts\python.exe -m pytest              # full offline suite
.venv\Scripts\python.exe -m pytest tests/test_modules.py -k visual -v
```

Watch for invariants:

* every `finding.evidence_ids` ⊆ report evidence IDs (asserted by `_assert_grounded`);
* `evidence_chain_valid is True`;
* trace lists `orchestrator → specialist → (url) → evidence → report`;
* `degraded is true` and `reasoning_mode == "offline-expert-system"` without a token;
* with `HF_TOKEN`: `mode: "llm-planner"`, `narrative_source: "huggingface"`,
  and reasoning steps marked `ok` instead of `skipped`.
