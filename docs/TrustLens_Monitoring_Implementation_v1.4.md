# TrustLens: Real-Time Protection and Domain/Certificate Monitoring
## Engineering Implementation Plan v1.4

**Scope:** Real-Time Phishing Pre-Screening (Fast Path), Proactive Lookalike/Homoglyph Monitoring, CA Distrust Intelligence Lifecycle, and Certificate Transparency (CT) Issuance Monitoring.  
**Document Status:** Final production implementation specification. Repository implementation progress is summarized in the status note at the end; the specification is not evidence that every phase is implemented.  
**Supersedes:** `docs/TrustLens_Monitoring_Implementation_v1.3.md`, `v1.2.md`, `v1.1.md`, and `v1.0.md`.  
**Authoritative Baselines:** `TrustLens_Module2_Implementation_v2.6.md`, `context.md`, `IMPLEMENTATION_CHECKLIST.md`, `src/links/services/analyser.py`, `src/links/services/risk.py`, `src/links/services/registry.py`, `src/links/services/redis_store.py`, `src/links/services/db.py`, and `src/links/services/tls/distrust.py`.

---

## 0. Project Priority Assessment & Roadmap Decision

> [!IMPORTANT]
> **Priority Decision (Sprint Agreement)**:
> The monitoring features in this document constitute an **optional 62.0-hour extension** that lies outside the mandatory evaluation score. The required core MVP deliverables—specifically the **AI Explanation Engine (Module 3)**, **Scam Content Analysis (Module 4)**, the **Decentralized Web3 Threat Registry & Verification (Module 6, representing 20% of the total score)**, and the **Threat Intelligence Dashboard**—remain unscheduled.
>
> **Formal Recommendation**: 
> 1. Lock this v1.4 implementation specification as verified and production-ready.
> 2. **Prioritize the Mandatory MVP deliverables first** to secure the core 80%+ evaluation score.
> 3. Schedule the 62.0-hour monitoring build order (Phases 1–5) only after the mandatory MVP modules achieve operational readiness.

### Core Non-Negotiable Invariants
1. **Safety Over Confidence**: Absence of indicators is never proof of safety. A pre-screen returning zero findings evaluates to `no_local_signals` with `confidence: "low"`, never `safe` or `low_risk`.
2. **Fixed Core Engine Gates**: `GATING_CHECKS` strictly remains the original 10 checks in `src/links/services/risk.py:21`. `CHECK_IDS` strictly remains 11 in `src/links/services/analyser.py:47`. Core pipeline definitions are untouched.
3. **Neutral Terminology**: Alerts and findings describe observable state ("resolving", "recently registered", "unrecognized issuer"), never speculative or emotive intent ("malicious", "threat", "attacker").
4. **Tenant Isolation & Strict User Privacy**: Alert evidence and API responses NEVER store or expose report UUIDs, submitted user URLs, or cross-tenant data. URLs submitted to the fast path are never persisted to disk or written to application logs (logging outputs only `url_sha256[:16]`). One tenant can never view, acknowledge, or dismiss another tenant's watches or alerts.
5. **Committed Cryptographic Provenance**: Distrust dataset updates require verified certificates committed to the repository. Manifest placeholders (e.g. `<ENTER... >`) are strictly rejected by automated build gates.

---

## 1. Verified Baseline & Repo Findings (Phase 1)

Every assertion in this section is verified against repository source code.

### 1.1 Repository Verification Findings Table

| # | Topic / Question | Verified Implementation in Repository | Exact Evidence (File & Line) | Confidence |
|---|---|---|---|---|
| **1** | **Check Runner & Subsets** | `@register_check(check_id, *, depends_on, timeout, needs_network)` registers specs into `CHECKS: dict[str, CheckSpec]`. `run_all(ctx, order)` enforces dependencies. `intel_urlhaus` has `depends_on=("normalise", "redirect_chain")`. If `redirect_chain` is omitted from `order`, `run_all` raises `ValueError: check dependencies contain a cycle or unknown check`. Fast-path screening runs `run_all(ctx, ["normalise", "lexical", "brand_impersonation"])` and executes `urlhaus.run(ctx.nurl.normalised)` directly. | `src/links/services/registry.py:34-79`<br>`src/links/services/analyser.py:276`<br>`src/links/models.py:65-69` | High |
| **2** | **Risk Engine & Gating** | `classify(findings, checks)` aggregates findings by evidence group. `GATING_CHECKS` is a frozen set of the original 10 Module 1 check IDs. `_ok_gating(checks)` checks only those 10. `risk="low"` strictly requires `len(ok) >= 7` AND external reputation OK (`intel_safebrowsing` or `intel_virustotal`). On a 4-check local subset, `len(ok) <= 4` and external reputation is false; `classify()` evaluates to `"inconclusive"` when clean, or `"suspicious"` / `"confirmed_malicious"` when findings fire. It cannot evaluate to `"low"`. | `src/links/services/risk.py:4-26` | High |
| **3** | **DL, Confusables, Brands, DNS** | `confusables.is_mixed_script()` and `is_confusable()` detect homoglyphs. `DamerauLevenshtein.distance()` calculates edit distance. `dns_check(host, registered_domain)` resolves A/AAAA/MX/NS/TXT and returns `(status, findings, reason)`. They are pure detectors; **zero candidate generator exists in the repo**. | `src/links/services/analyser.py:18-19, 50, 108-124`<br>`src/links/services/checks/network.py:10-35` | High |
| **4** | **`tldextract` Network Behavior** | Configured with `_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)`. Empty `suffix_list_urls=()` disables network downloads and forces reliance on the bundled snapshot. Zero network calls occur on the hot path. | `src/links/services/checks/normalise.py:9` | High |
| **5** | **URLhaus Redis Lookup API** | `redis_store.lookup(url)` fetches active generation via `r.get("urlhaus:v1:active_generation")` (raises `RuntimeError` if absent). Queries `urlhaus:v1:{gen}:{active|historical}:{url|host}:{sha256}`. `checks/urlhaus.py` catches exceptions and returns `("unavailable", [], str(exc))`. Active exact URL/host matches set `active_confirmation_eligible=True`. If Redis is down, it yields empty findings and unavailable status. | `src/links/services/redis_store.py:26-38`<br>`src/links/services/checks/urlhaus.py:4-12` | High |
| **6** | **Database Migrations** | Startup in `db.open_pool()` checks `schema_migrations` table, reads sorted `src/links/migrations/*.sql`, executes statements split on `;`, and records applied migration. Latest migration is `001_initial.sql`. Uses `UUID PRIMARY KEY`, `TIMESTAMPTZ`, and `JSONB`. | `src/links/services/db.py:17-25`<br>`src/links/migrations/001_initial.sql:1-24` | High |
| **7** | **Auth, Limiter & CORS** | No API key or user authentication exists for public routes. `slowapi.Limiter(key_func=get_remote_address)` rate-limits per remote IP (`20/minute` on `/api/v1/analyse/url`). CORS middleware uses `CORS_ALLOW_ORIGINS` (default `http://localhost:3000`). Extensions (`chrome-extension://<id>`) are currently blocked unless explicitly configured in the environment. | `src/links/routes.py:12-25`<br>`src/main.py:18-24` | High |
| **8** | **CA Distrust Dataset** | Loaded via `load_dataset()` in `distrust.py:42-72`. Validates committed PEM SHA-256 against `manifest.json`. Current repo manifest has 1 verified record: `em-dv-tls-ca-g3b` (eMudhra BV, SHA-256 `42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493`, Bugzilla 2083449). `load_dataset` accepts any classification string; `analyser.py:391` checks `r.classification == "compromised"` else defaults to `D.DISTRUSTED`. `bytes.fromhex()` handles uppercase and lowercase hex. Crucially, **`match_distrust` function does not exist in `distrust.py`**; matching is implemented in `analyser.py:380-394`. | `src/links/services/tls/distrust.py:42-72`<br>`src/links/data/ca_distrust/manifest.json:1-17`<br>`src/links/services/analyser.py:380-394` | High |
| **9** | **WebSockets Dependency** | `websockets>=17.4` is installed transitively via `uvicorn[standard]>=0.54.0`. To guarantee deterministic worker builds across minimal containers, it must be explicitly declared in `pyproject.toml`. | `pyproject.toml:10`<br>`uv pip list` | High |
| **10**| **`report->'tls_reports'` Persistence Verification** | `src/links/models.py:129` defines `tls_reports: dict[str, TLSReport] | None = None` on `Report`. `analyser.py:508` sets `tls_reports=ctx.values.get("tls_reports")`. `db.py:42` executes `INSERT INTO reports(id,submitted_url,report,expires_at) VALUES (%s,%s,%s,%s)` with `Jsonb(saved.model_dump(mode="json"))`. When an HTTP URL is analyzed, `tls_reports` serializes as `null`. Serialization logic exists in code, but integration tests in `test_postgres.py` only asserted reports without TLS data. **Status: UNVERIFIED live roundtrip; manual verification gate required before Phase 4.** | `src/links/models.py:129`<br>`src/links/services/analyser.py:508`<br>`src/links/services/db.py:42`<br>`tests/integration/test_postgres.py:59` | **UNVERIFIED (Requires Gate)** |
| **11**| **Fetcher Probe Contract & Semaphore** | Fetcher runs at `FETCHER_BASE_URL` with endpoints `/fetch`, `/probe/tls`, `/probe/headers`. Guard uses 4-slot concurrency semaphore. Requires `X-Fetcher-Token: FETCHER_TOKEN`. TLS probe accepts `host`, `port`, `timeout_budget` (spec $\le 8.0\text{s}$). Re-probe must consume no more than 2 slots. | `fetcher/server.py`<br>`src/links/services/analyser.py:328-356` | High |
| **12**| **Report Storage & Retention** | Reports stored in `reports` table with `expires_at = now() + 7 days`. Table columns are `id`, `submitted_url`, `report`, `created_at`, `expires_at`. `created_at` exists as a table column, NOT inside JSONB. Stored report JSON contains top-level keys `report_id`, `input`, `risk_class`, `confidence`, `coverage`, `findings`, `redirect_chain`, `tls_reports`. | `src/links/services/db.py:38-42`<br>`src/links/migrations/001_initial.sql:1-12` | High |
| **13**| **Check Spec Count Invariants** | `CHECK_IDS` contains exactly 11 checks. `GATING_CHECKS` contains exactly 10 checks. Existing tests assert `len(CHECKS) == 11` and coverage completed/planned counts. No monitoring feature may change these collections. | `src/links/services/analyser.py:47`<br>`src/links/services/risk.py:21`<br>`tests/unit/test_checks.py:12` | High |
| **14**| **DNS Probe Capabilities** | `network.dns_check` uses `dnspython` `resolver.resolve()`. Currently performs A, AAAA, MX, NS, TXT lookups using system default resolvers. Pure detection; no bulk throttling, concurrency controls, or wildcard UUID baselines exist. | `src/links/services/checks/network.py:10-45` | High |
| **15**| **Redis Key Naming Schema** | Active URLhaus data keyed as `urlhaus:v1:{gen}:{active|historical}:{url|host}:{sha256}`. Active generation stored at `urlhaus:v1:active_generation`. Monitoring deduplication should not collide with URLhaus namespaces. | `src/links/services/redis_store.py:12-40` | High |
| **16**| **Windows Event Loop Constraints** | Default Windows Proactor loop causes connection resets and broken pipe errors under multi-threaded async Psycopg pool loads. Must use `asyncio.WindowsSelectorEventLoopPolicy()` in long-running daemons. | `src/links/services/runtime.py:1-15` | High |

---

## 2. Architectural Decisions (Locked)

| Decision | Topic | Status | Architectural Rule |
|---|---|---|---|
| **D1** | **Fast-Path Check Isolation** | Fixed | Fast path runs `run_all` on `["normalise", "lexical", "brand_impersonation"]` and calls `urlhaus.run()` directly, bypassing `redirect_chain` and its network overhead. |
| **D2** | **Risk Engine Verdict Mapping** | Fixed | Fast path passes the 4 check outputs to `risk.classify()`. Active URLhaus exact/host match yields `block` (`confidence: "high"`); Suspicious or higher yields `warn` (`confidence: "medium"`); anything else (clean or weak-only) yields `no_local_signals` (`confidence: "low"`). |
| **D3** | **Dual Unfiltered Resolvers with Short-Circuit** | Fixed | Candidate DNS probing queries unfiltered Quad9 (`9.9.9.10`) and Cloudflare (`1.1.1.1`). Resolvers run in parallel; if the first returns an A/AAAA record, resolution is confirmed immediately. MX and RDAP queries run ONLY for candidates that resolve. Disagreements are logged. A "not resolving" verdict waits for both resolvers. |
| **D4** | **Silent First Scan & Lookalike Cadence** | Fixed | `lookalike_scanned_at` timestamp on `watch_domains` gates alerting. First scan populates `lookalike_state` silently with 0 alerts. Rescans occur every 24 hours per watch. Candidates discovered on subsequent rescans are also recorded silently. |
| **D5** | **Consolidated Transition Alerting & MX Split** | Fixed | One event emits exactly ONE consolidated alert at the highest severity. MX present on first resolving observation is `strong` (`lookalike_resolving_with_signals`); MX added to an already resolving domain is `moderate` (`lookalike_new_mx_record`). Rationale: a newly live domain with mail infrastructure indicates immediate active phishing capability. |
| **D6** | **Privacy & Fast-Path URL Privacy** | Fixed | Alert evidence NEVER contains report UUIDs or raw submitted URLs. Fast-path pre-screen NEVER persists submitted URLs to PostgreSQL or application logs (logs output only `url_sha256[:16]`). Supports `mode: "full"` and `mode: "host_only"`. |
| **D7** | **Template-Only Distrust Manifest** | Fixed | Unverified manifest entries in docs/plans are strictly marked template-only. Build verification tests reject placeholders (`<ENTER... >`) to protect `bytes.fromhex()`. |
| **D8** | **Registered Domain Validation (eTLD+1)** | Fixed | Watch targets must be registered domains (eTLD+1). Subdomains (`app.example.com`) are rejected with HTTP 400. |
| **D9** | **crt.sh Resilient Backfill, Org Normalization & Manual Issuer Trust** | Fixed | Baseline backfill queries crt.sh once per watch with retry backoff (`next_backfill_at`). Normalizes issuer Organization (`O`), falling back to `CN`, stripping corporate suffixes (`Inc`, `LLC`, `B.V.`). An alert acknowledgment or dismissal with `trust_issuer: true` inserts the issuer into `domain_issuer_baseline`. |
| **D10**| **4-Condition CT Pre-Filter & Punycode Decoding** | Fixed | CT stream pre-filter drops a certificate in memory ONLY IF all 4 conditions fail: (1) own-domain suffix, (2) watched brand label substring, (3) length-bounded edit distance ($\ge 6$), (4) exact membership in the candidate set. Decode `xn--` punycode labels before any label comparison. |
| **D11**| **Authenticated Watch, Alert & Status APIs** | Fixed | Full CRUD for watches, list/ack/dismiss for alerts, and system health status (`GET /api/v1/monitor/status`) with tenant isolation (`owner_id`), pagination, and rate limiting (`60/minute`). Counts in `/monitor/status` are scoped to the calling owner. |
| **D12**| **Independent Worker Task Architecture** | Fixed | Single `worker.py` daemon runs independent `asyncio` task loops for Lookalike scanning, Backfill, Retro-scan, Re-probe, CT streaming, and Maintenance, with periodic `SELECT 1` heartbeat on the advisory lock connection. |
| **D13**| **Cross-Tenant Deduplication & History Preservation** | Fixed | `ct_seen_certs` dedupe key includes `watch_id`: `SHA-256(watch_id + ":" + issuer_org + ":" + serial_hex + ":" + san_apex)`. Inserted strictly AFTER the tenant alert is written. `monitoring_alerts.watch_id` uses `ON DELETE SET NULL` to preserve historical alerts when a watch is removed. |
| **D14**| **Explicit Direct Dependency Pinning** | Fixed | Explicitly pin `websockets>=17.4` in `pyproject.toml` dependencies. |

---

## 3. Shared Foundation Architecture

### 3.1 Migration DDL (`src/links/migrations/002_monitoring.sql`)

Conforms to repository database conventions (`UUID PRIMARY KEY`, `TIMESTAMPTZ`, `JSONB`, snake_case).

```sql
-- Migration 002: Monitoring Foundation, Watchlists, State, and Alerts

-- API Key / Tenant Registry
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active BOOLEAN NOT NULL DEFAULT true
);

-- Watched Domains (Registered Domains eTLD+1 Only)
CREATE TABLE IF NOT EXISTS watch_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id TEXT NOT NULL,
    domain_ascii TEXT NOT NULL,
    domain_display TEXT NOT NULL,
    known_own_domains TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    baseline_done BOOLEAN NOT NULL DEFAULT false,
    baseline_empty BOOLEAN NOT NULL DEFAULT false,
    backfill_attempts INTEGER NOT NULL DEFAULT 0,
    next_backfill_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_ct_log_id BIGINT NOT NULL DEFAULT 0,
    lookalike_scanned_at TIMESTAMPTZ,
    last_probed_at TIMESTAMPTZ,
    last_backfill_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(owner_id, domain_ascii)
);
CREATE INDEX IF NOT EXISTS watch_domains_owner_idx ON watch_domains(owner_id) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS watch_domains_scan_idx ON watch_domains(lookalike_scanned_at) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS watch_domains_backfill_idx ON watch_domains(next_backfill_at) WHERE enabled = true AND baseline_done = false;

-- Lookalike State Tracking (Enables Transition-Only Alerting)
CREATE TABLE IF NOT EXISTS lookalike_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    watch_id UUID NOT NULL REFERENCES watch_domains(id) ON DELETE CASCADE,
    candidate_ascii TEXT NOT NULL,
    resolves BOOLEAN NOT NULL,
    has_mx BOOLEAN NOT NULL DEFAULT false,
    mx_host TEXT,
    rdap_age_days INTEGER,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_checked TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(watch_id, candidate_ascii)
);
CREATE INDEX IF NOT EXISTS lookalike_state_watch_idx ON lookalike_state(watch_id);

-- Own-Domain Authorized CA Issuer Baseline (Normalized Organization)
CREATE TABLE IF NOT EXISTS domain_issuer_baseline (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    watch_id UUID NOT NULL REFERENCES watch_domains(id) ON DELETE CASCADE,
    issuer_org TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(watch_id, issuer_org)
);

-- Generic Alert Store (ON DELETE SET NULL preserves alert history)
CREATE TABLE IF NOT EXISTS monitoring_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id TEXT NOT NULL,
    watch_id UUID REFERENCES watch_domains(id) ON DELETE SET NULL,
    kind TEXT NOT NULL, -- 'lookalike_transition' | 'ca_distrust' | 'ct_issuance'
    severity TEXT NOT NULL, -- 'info' | 'moderate' | 'strong'
    status TEXT NOT NULL DEFAULT 'new', -- 'new' | 'acknowledged' | 'dismissed'
    target TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    evidence JSONB NOT NULL,
    source TEXT NOT NULL,
    dismiss_reason TEXT,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at TIMESTAMPTZ,
    limitations JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS monitoring_alerts_owner_status_idx ON monitoring_alerts(owner_id, status);
CREATE INDEX IF NOT EXISTS monitoring_alerts_watch_idx ON monitoring_alerts(watch_id);

-- Worker Task State and Watermarks
CREATE TABLE IF NOT EXISTS monitor_state (
    task_name TEXT PRIMARY KEY,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_run_at TIMESTAMPTZ,
    last_error TEXT,
    state JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- CT Issuance Deduplication Cache (Matches Only, Pruned Daily)
CREATE TABLE IF NOT EXISTS ct_seen_certs (
    cert_dedupe_hash TEXT PRIMARY KEY, -- SHA-256(watch_id + ":" + issuer_org + ":" + serial_hex + ":" + san_apex)
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ct_seen_certs_seen_at_idx ON ct_seen_certs(seen_at);
```

---

### 3.2 Authentication & Rate Limiting Infrastructure

1. **Authentication Dependency (`src/links/services/auth.py`)**:
   - Extracts `X-API-Key` header from requests.
   - Computes `key_hash = hashlib.sha256(api_key.encode()).hexdigest()`.
   - Queries `api_keys` via `db.pool`. Rejects invalid/inactive keys with HTTP 401.
   - Attaches authenticated `owner_id` and `api_key_hash` to `request.state`.
2. **Two-Tier Rate Limiting (Preventing Unauthenticated DB Lookups)**:
   - **Tier 1 (IP Limiter)**: `slowapi` applies `get_remote_address` globally to all incoming monitoring endpoints (`120/minute`) BEFORE authentication or database lookups. An attacker sending random API keys cannot cause unbound database lookups.
   - **Tier 2 (Per-Key Limiter)**: A custom key function `get_authenticated_key(request: Request) -> str` executes AFTER authentication, using `request.state.api_key_hash`. Enforces `60/minute` per validated tenant.
3. **Key Creation Script (`scripts/create_api_key.py`)**:
   - Generates `"tl_live_" + secrets.token_hex(24)`.
   - Computes SHA-256 hash and writes `(key_hash, owner_id, label)` to `api_keys`.
   - Prints raw key to stdout once. Raw key is never stored or logged.
4. **CORS Extension Configuration (`src/main.py`)**:
   - Configures CORS middleware regex origin validator to permit `chrome-extension://[a-z]{32}` origins alongside `CORS_ALLOW_ORIGINS`.
   - Explicitly adds `X-API-Key` to `CORS_ALLOW_HEADERS`.

---

### 3.3 Watch Management API (`src/links/routes_watch.py`)

Rate limit: `60/minute` per API key.
- **`POST /api/v1/monitor/watch`**:
  - Request: `{"domain": "example.com", "known_own_domains": ["example.net", "example.org"]}`.
  - Validation:
    - Normalizes domain using `idna.encode(domain.strip().lower(), uts46=True).decode('ascii')`.
    - Rejects IP literals. Length $\le 253$ chars; labels $\le 63$ chars.
    - **Registered Domain Check**: Uses `tldextract`. Extracted `suffix` must be non-empty and `subdomain` must be empty (`ext.registered_domain == domain_ascii`). Subdomains (`app.example.com`) return HTTP 400 (`"Watch target must be a registered domain (eTLD+1), not a subdomain"`).
    - Owner quota: Queries count of active watches for `owner_id`. If $\ge 20$, returns HTTP 400 (`"Owner watch limit of 20 domains reached"`).
    - Normalizes and validates each entry in `known_own_domains` (max 50 entries).
  - Inserts into `watch_domains` with `baseline_done = false` and `lookalike_scanned_at = NULL`.
  - Returns HTTP 201 Created.
- **`GET /api/v1/monitor/watch`**:
  - Returns `list[WatchDomainResponse]` for authenticated `owner_id`.
- **`DELETE /api/v1/monitor/watch/{id}`**:
  - Deletes row where `id = %s AND owner_id = %s`. Cascades to state and baseline tables; linked alerts have `watch_id` set to `NULL` to preserve security history. Returns HTTP 204 No Content.

---

### 3.4 Alerts Management API (`src/links/routes_alert.py`)

Rate limit: `60/minute` per API key. All endpoints strictly enforce tenant isolation (`owner_id = authenticated_owner_id`).
- **`GET /api/v1/monitor/alerts`**:
  - Query parameters:
    - `status`: Optional filter (`new` | `acknowledged` | `dismissed`).
    - `severity`: Optional filter (`info` | `moderate` | `strong`).
    - `kind`: Optional filter (`lookalike_transition` | `ca_distrust` | `ct_issuance`).
    - `watch_id`: Optional UUID filter.
    - `limit`: Integer (default 50, max 200).
    - `offset`: Integer (default 0).
  - Returns `{ "alerts": [AlertResponse], "total": count, "limit": limit, "offset": offset }`.
- **`POST /api/v1/monitor/alerts/{id}/ack`**:
  - Request body: `{"trust_issuer": false}` (optional boolean).
  - If `trust_issuer: true` AND alert is `ct_issuance` with a valid `watch_id`:
    - Extracts `norm_org = alert.evidence["issuer_org"]`.
    - Inserts into `domain_issuer_baseline (watch_id, issuer_org) VALUES (%s, %s) ON CONFLICT DO NOTHING`.
  - Updates alert: `UPDATE monitoring_alerts SET status = 'acknowledged', acknowledged_at = now() WHERE id = %s AND owner_id = %s`.
  - Returns HTTP 200 with updated alert, or HTTP 404 if not found or unauthorized.
- **`POST /api/v1/monitor/alerts/{id}/dismiss`**:
  - Request body: `{"reason": "string (optional)", "trust_issuer": false}`.
  - If `trust_issuer: true`, inserts `issuer_org` into `domain_issuer_baseline` as above.
  - Dismisses alert: `UPDATE monitoring_alerts SET status = 'dismissed', dismiss_reason = %s WHERE id = %s AND owner_id = %s`.
  - Returns HTTP 200 with updated alert, or HTTP 404 if not found or unauthorized.

---

### 3.5 Status & Observability API (`src/links/routes_status.py`)

- **`GET /api/v1/monitor/status`**:
  - Requires `X-API-Key`.
  - Scopes counts (`pending_watches`, `active_alerts`) strictly to the authenticated `owner_id`:
    ```json
    {
      "worker_running": true,
      "advisory_lock_held": true,
      "ct_stream": {
        "status": "connected",
        "stream_gaps_15m": 0,
        "last_message_at": "2026-11-09T10:14:22Z"
      },
      "tenant_metrics": {
        "owner_id": "tenant_123",
        "active_watches": 4,
        "pending_rescans": 1,
        "unacknowledged_alerts": 2
      },
      "system_state": {
        "ca_distrust_version": "trustlens-ca-distrust-2026-11-09+1-verified"
      }
    }
    ```

---

### 3.6 Background Worker Daemon (`worker.py`)

Standalone process executing outside Uvicorn, strictly using `asyncio.SelectorEventLoop` on Windows to preserve Psycopg connection pool stability.
- **Heartbeat & Advisory Lock**: Acquires 32-bit advisory lock `948201`. Executes a periodic `SELECT 1` heartbeat every 15s on the dedicated locking connection. If the heartbeat fails, the worker exits immediately to allow container restart.

```python
# worker.py independent task architecture
async def run_worker_loop():
    await db.open_pool()
    try:
        async with db.pool.connection() as conn:
            res = await (await conn.execute("SELECT pg_try_advisory_lock(%s)", (WORKER_LOCK_ID,))).fetchone()
            if not res or not res[0]:
                print("Another worker instance is holding the advisory lock. Exiting.")
                return

            print("TrustLens background worker acquired lock. Initializing runners...")
            await asyncio.gather(
                safe_loop(heartbeat_loop, "heartbeat", conn),
                safe_loop(lookalike_scan_loop, "lookalike_scanner"),
                safe_loop(crt_backfill_loop, "backfill_runner"),
                safe_loop(ca_retroscan_loop, "ca_retroscanner"),
                safe_loop(ca_reprobe_loop, "ca_reprober"),
                safe_loop(ct_stream_consumer_loop, "ct_stream"),
                safe_loop(maintenance_purge_loop, "maintenance")
            )
    finally:
        await db.close_pool()
```

#### Independent Worker Task Loops
1. **`lookalike_scan_loop`**: Runs every 60s. Queries watches where `enabled = true AND (lookalike_scanned_at IS NULL OR lookalike_scanned_at < now() - interval '24 hours') ORDER BY lookalike_scanned_at NULLS FIRST LIMIT 2`. Probes candidates with DNS short-circuiting. Sets `lookalike_scanned_at = now()` strictly AFTER all state changes are committed.
2. **`crt_backfill_loop`**: Runs every 30s. Queries watches where `enabled = true AND baseline_done = false AND next_backfill_at <= now() LIMIT 5`. Caps crt.sh response size at 10 MB. On failure, increments `backfill_attempts` and sets `next_backfill_at = now() + backoff_interval` (5m, 15m, 1h, 6h).
3. **`ca_retroscan_loop`**: Runs every 120s. Checks if `manifest.version != monitor_state['state']->>'last_distrust_version'`. Batches report reads in chunks of 500.
4. **`ca_reprobe_loop`**: Runs every 300s. Queries watches where `last_probed_at IS NULL OR last_probed_at < now() - interval '24 hours' LIMIT 2`. Re-probes apex, updates `last_probed_at = now()` unconditionally.
5. **`ct_stream_consumer_loop`**: Ingests live CT certificates or executes fallback poller. Marks status `DEGRADED_NO_EGRESS` after 5 consecutive dual failures.
6. **`maintenance_purge_loop`**: Runs daily at 03:00 UTC. Deletes `monitoring_alerts` older than 90 days and `ct_seen_certs` older than 30 days.

---

## 4. Feature Specifications

### 4.1 Feature A: Real-Time Phishing Protection (Fast-Path Pre-Screen)

#### Pipeline Flow
1. **Normalize**: `normalise.py`. Fails $\to$ HTTP 400.
2. **Local Checks**: `run_all(ctx, ["normalise", "lexical", "brand_impersonation"])`.
3. **URLhaus Redis Lookup**: If `mode == "full"`, queries `urlhaus.run(ctx.nurl.normalised)`. If `mode == "host_only"`, queries host-level key `urlhaus:v1:{gen}:active:host:{sha256}`.
4. **Risk Engine Classification**: Passes the 4 check outputs to `risk.classify(findings, checks)`.
   - Active URLhaus exact or host match $\to$ VERDICT: `"block"`, `confidence: "high"`.
   - `risk.classify()` in `("confirmed_malicious", "high", "suspicious")` $\to$ VERDICT: `"warn"`, `confidence: "medium"`.
   - Otherwise (clean, weak-only findings, or `risk.classify()` returns `inconclusive`) $\to$ VERDICT: `"no_local_signals"`, `confidence: "low"`.

#### API Contract (`POST /api/v1/screen/url`)
- **Request Schemas (Discriminated Union)**:
  ```json
  // Full URL Request
  { "url": "https://paypa1-security-update.com/login", "mode": "full" }

  // Host-Only Privacy Request
  { "host": "paypa1-security-update.com", "mode": "host_only" }
  ```
- **Response (`200 OK`)**:
  ```json
  {
    "target_sha256": "4b68ff5c8e2a392b4a53018e69d7a96d1945d7a8d5696c21e7d23589b37c0eb8",
    "verdict": "warn",
    "confidence": "medium",
    "coverage": { "completed": 4, "planned": 10, "scope": "local_pre_screen" },
    "findings": [
      { "id": "brand_impersonation.typosquat", "title": "Possible paypal typosquat", "severity": "strong" }
    ],
    "limitations": [
      "Fast path evaluates local lexical and threat feed indicators only. Absence of indicators does not guarantee safety."
    ],
    "evaluated_at": "2026-11-09T09:40:00Z",
    "elapsed_ms": 3
  }
  ```
- **Privacy Preservation**: Submitted URLs are NEVER saved to PostgreSQL or printed in application logs. Application logs output only `url_sha256[:16]`.

---

### 4.2 Feature B1: Proactive Lookalike & Homoglyph Monitoring

#### Candidate Generation Engine (`src/links/services/monitoring/generator.py`)
Generates up to 500 ordered variations using deterministic permutation algorithms (omission, transposition, homoglyphs via `confusable_homoglyphs`, hyphenation, bitsquatting, combosquatting).
- Formats variants to lowercase ASCII punycode via `idna.encode()`.
- **Strict Exclusions**: Excludes `watch.domain_ascii` and all domains in `watch.known_own_domains`.
- Output capped strictly at 500 candidates.

#### Safe Public DNS Probing with Short-Circuiting
- **Dual Unfiltered Resolvers**: Queries Quad9 unfiltered (`9.9.9.10`) and Cloudflare (`1.1.1.1`).
- **Resolution Safety & Short-Circuiting**: Resolvers run in parallel. If the first responding resolver returns an A or AAAA record, the domain is confirmed as **resolving immediately**. A "not resolving" verdict requires both resolvers to respond.
- **Conditional Querying**: MX and RDAP lookups run **ONLY for candidates that resolve**.
- Concurrency semaphore: 20. Timeout: 2.0s per lookup. Rate limit: $\le 10$ queries/second.
- **Wildcard Detection Baseline**: Queries `rand-<uuid>.<tld>`. If it resolves, probing is aborted and target marked `wildcard_dns_detected`.

#### Consolidated Transition-Only Alerting Matrix
Only state transitions from `lookalike_state` emit alerts. **Exactly ONE consolidated alert is emitted per candidate evaluation at the highest severity.**

| Transition Scenario | Highest Severity | Consolidated Alert Type | Evidence Payload Contents |
|---|---|---|---|
| Resolving + MX (First sight of live domain) | `strong` | `lookalike_resolving_with_signals` | `{resolves: true, has_mx: true, mx_host: "...", rdap_age_days: 12}` |
| Resolving (No MX, RDAP $\ge 30$d or unknown) | `info` | `lookalike_now_resolving` | `{resolves: true, has_mx: false, rdap_age_days: null}` |
| Already resolving domain: MX record added later | `moderate` | `lookalike_new_mx_record` | `{resolves: true, has_mx: true, mx_host: "..."}` |
| Already resolving domain: RDAP confirmed $< 30$d | `strong` | `lookalike_recent_registration_confirmed` | `{resolves: true, rdap_age_days: 14}` |
| Already resolving domain: MX provider changed | `moderate` | `lookalike_mx_provider_changed` | `{old_mx: "...", new_mx: "..."}` |

- **Silent First Scan & New Candidates**: When `lookalike_scanned_at IS NULL`, or when new permutation candidates appear on later scans, they are recorded silently into `lookalike_state`. Zero alerts fire on first observation.
- **Flapping Protection**: Dedupe key format: `lookalike:{owner_id}:{watch_id}:{candidate_ascii}:{highest_transition_type}`. Uses `INSERT INTO monitoring_alerts ... ON CONFLICT (dedupe_key) DO NOTHING`. Suppresses repeated alerts for identical transitions over the 90-day alert retention period.
- **RDAP Missing Data**: When RDAP is rate-limited or unavailable, `rdap_age_days` remains `NULL` ("unknown"). It never lowers risk or defaults to clean.

---

### 4.3 Feature B2: CA Distrust Intelligence Lifecycle & Retro-Scan

#### Dataset Rules & Provenance Verification
- Manifest: `src/links/data/ca_distrust/manifest.json`.
- Manual verification: Commit PEM to `certs/<id>.pem`, compute SHA-256 fingerprint in code, cross-check against primary CCADB/Mozilla advisory, record `retrieved_on`.
- Build verification gate (`test_manifest_no_placeholders`): Rejects any entry containing `<ENTER` or non-hex string to guarantee `bytes.fromhex()` never raises `ValueError`.

#### Manifest Expansion Specification
```json
{
  "version": "trustlens-ca-distrust-2026-11-09-v2",
  "records": [
    {
      "id": "em-dv-tls-ca-g3b",
      "entity": "eMudhra BV",
      "classification": "compromised",
      "source_url": "https://bugzilla.mozilla.org/show_bug.cgi?id=2083449",
      "certificate_url": "https://ctlogs.dev/ca/42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493/cert.pem",
      "source_record": "Mozilla Bugzilla 2083449: CCADB A012302, serial a4aee678f23362b4c0e460b772f214, SHA-256 42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493",
      "retrieved_on": "2026-11-09",
      "cert_file": "certs/em-dv-tls-ca-g3b.pem",
      "expected_cert_sha256": "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493",
      "scope": { "type": "all" }
    }
  ]
}
```
*Note: Additional records (DigiNotar, WoSign) must be populated with verified CCADB values prior to commit. Never commit placeholder records.*

#### Retro-Scan Job (`ca_retroscan_loop`)
Triggered when `manifest.version != monitor_state['state']->>'last_distrust_version'`:
1. **Historical Report Scan**:
   - Queries unexpired reports in batches of 500:
     ```sql
     SELECT id, report, created_at FROM reports 
     WHERE expires_at > now() 
       AND report ? 'tls_reports' 
       AND jsonb_typeof(report->'tls_reports') = 'object'
     ORDER BY id LIMIT 500 OFFSET %s;
     ```
   - Iterates `report['tls_reports'].items()`, extracting `authority_key` (`host:port`).
   - Safely parses host for IPv4 and IPv6:
     ```python
     host = authority_key.rsplit(":", 1)[0].strip("[]")
     ```
   - Matches leaf and chain fingerprints against distrust dataset.
   - If matched: matches `host` against `watch_domains` across all owners.
   - **Privacy Protection**: Alert evidence **NEVER stores report UUID or submitted URL**.
     - Evidence payload: `{"matched_authority": authority_key, "distrust_record_id": record.id, "fingerprint_sha256": fp_hex, "observed_at": row["created_at"].isoformat()}`.
     - **Stable Dedupe Key (Excluding Version)**: `cadistrust:{owner_id}:{authority_key}:{distrust_record_id}`. Manifest version bumps will not re-alert on already alerted records.
2. **Active Re-Probe (`ca_reprobe_loop`)**:
   - Re-probes apex `watch_domains` targets where `last_probed_at IS NULL OR last_probed_at < now() - interval '24 hours'`.
   - Sends probe request to fetcher `/probe/tls` with `timeout_budget=8.0`, port 443, supplying `X-Fetcher-Token`.
   - Reuses Module 2's distrust evaluation path (`analyser.py:380-394`).
   - If matched, creates `cadistrust` alert for watch owner.
   - **Updates `last_probed_at = now()` unconditionally** on both success and connection failure, preventing broken hosts from being probed continuously.
   - Bounded to 2 concurrent probes (leaving 2 slots free on fetcher's 4-slot semaphore).
   - Limitation: Apex only (`domain_ascii:443`). Subdomains (`www`, `mail`) are not probed.
3. **Route-Level Live Analysis Hook**:
   - Located in `src/links/routes.py` inside `/api/v1/analyse/url` after `report` is saved.
   - Scheduled via `background_tasks.add_task(check_and_emit_distrust_alert, report)`.
   - Fully isolated: wrapped in `try...except Exception: log.exception("Monitoring hook error")`. Zero impact on analysis response.

---

### 4.4 Feature B3: Certificate Transparency (CT) Issuance Monitoring

#### CT Source Abstraction & Test Replay Fixture
```python
# src/links/services/monitor/ct_source.py
from abc import ABC, abstractmethod
from pathlib import Path
import json

class CTSource(ABC):
    @abstractmethod
    async def connect(self): ...
    @abstractmethod
    async def messages(self): ...

class WebSocketCTSource(CTSource):
    """Production live Certificate Transparency stream consumer."""
    def __init__(self, uri="wss://certstream.calidog.io"):
        self.uri = uri
    async def connect(self):
        # connects via websockets.connect(self.uri, max_size=2*1024*1024)
        ...
    async def messages(self): ...

class ReplayFixtureCTSource(CTSource):
    """Deterministic offline test fixture yielding JSONL certificate records."""
    def __init__(self, fixture_path: Path):
        self.lines = fixture_path.read_text(encoding="utf-8").splitlines()
    async def connect(self):
        pass
    async def messages(self):
        for line in self.lines:
            if line.strip(): yield json.loads(line)
```

#### Baseline Backfill Task (`crt_backfill_loop`)
For each watch where `baseline_done == false AND next_backfill_at <= now()`:
- Queries `https://crt.sh/?q=<domain>&output=json` with a 15s timeout, capping response size at 10 MB.
- On timeout, HTTP error, or JSON failure: increments `backfill_attempts`, sets `next_backfill_at = now() + interval` (5m, 15m, 1h, max 6h), leaves `baseline_done = false`. CT Rule 1 remains dormant.
- If crt.sh returns `[]`: marks `baseline_done = true` and `baseline_empty = true`. The first observed CT certificate emits an `info` alert (`ct.initial_baseline_established`) prompting the owner to review and confirm with `trust_issuer: true`.
- **Organization Normalization**: Normalizes issuer Organization (`O`) into `domain_issuer_baseline`:
  - Parses issuer string into attribute dictionary.
  - Falls back to Common Name (`CN`) if `O` is absent.
  - Normalizes corporate suffixes: strips trailing punctuation, `"Inc"`, `"LLC"`, `"B.V."`, `"Ltd"`.
  - Result: `norm_org = clean_org(issuer_attrs.get("O") or issuer_attrs.get("CN", "UNKNOWN"))`.
- Sets `baseline_done = true`.

#### 4-Condition In-Memory Pre-Filtering & Untrusted Input Handling
1. **Untrusted Input Sanitization**:
   - WebSocket message frame cap: `max_size = 2 * 1024 * 1024` (2 MB).
   - Capped at 253 characters per SAN; max 50 SANs per certificate (excess discarded).
   - Non-printable and control characters stripped.
   - Malformed IDNA strings discarded without raising exceptions.
2. **Punycode Decoding**:
   - All `xn--` punycode labels are decoded to Unicode before performing brand label substring or edit distance matching.
3. **4-Condition Pre-Filter**:
   - A certificate is processed by the matching engine ONLY IF at least one SAN satisfies:
     1. Own-domain suffix: `san == watch.domain_ascii OR san.endswith("." + watch.domain_ascii)`.
     2. Brand label substring: Watched domain's brand label appears as an exact label or substring within a label.
     3. Length-bounded candidate: Brand label length $\ge 6$ and edit distance $\le 2$.
     4. Exact candidate set match: Registered domain matches an active candidate in `lookalike_state` (enabling Rule 2 to catch short-brand and homoglyph lookalikes).
   - Certificates failing all four are **discarded immediately in memory** without database writes.
4. **Cross-Tenant Deduplication Safety**:
   - `ct_seen_certs` records: `SHA-256(watch_id + ":" + norm_org + ":" + serial_hex + ":" + san_apex)`.
   - Recorded strictly AFTER the alert insert succeeds.
5. **Deduplication Key Format**:
   - `ct:{owner_id}:{watch_id}:{rule}:{cert_dedupe_hash}`.

#### Targeted Matching Pipeline (Strict Priority Order, First Match Wins)
For each normalized SAN:
1. **Own-Domain Rule**:
   - Condition: SAN matches `watch.domain_ascii` or ends with `"." + watch.domain_ascii`.
   - Gate: Alerting disabled until `watch.baseline_done == true`.
   - Logic: If issuer `norm_org` is not in `domain_issuer_baseline` $\to$ Alert `ct.unrecognized_issuer` (`severity: strong`).
2. **Exact Candidate Set Match**:
   - Condition: Registered domain matches a candidate in `lookalike_state` $\to$ Alert `ct.lookalike_cert_issued` (`severity: strong`).
3. **Brand-in-Subdomain**:
   - Condition: Watched brand label appears as a subdomain label while registered domain differs (`yourbank.com.evil.net`) $\to$ Alert `ct.brand_in_subdomain_cert` (`severity: strong`).
4. **Combosquatting**:
   - Condition: Watched brand label concatenated with security keyword (`login`, `verify`, `account`, `secure`, `portal`) inside registered domain label $\to$ Alert `ct.combosquat_cert` (`severity: moderate`).
5. **Length-Bucket Edit Distance**:
   - Length $< 6$: Distance matching disabled (0 distance, no fuzzy matches, preventing short brands like `sbi` from flooding).
   - Length $6 \le L < 10$: Damerau-Levenshtein distance $\le 1$ against watched brand label $\to$ Alert `ct.similar_name_cert` (`severity: moderate`).
   - Length $L \ge 10$: Damerau-Levenshtein distance $\le 2$ against watched brand label $\to$ Alert `ct.similar_name_cert` (`severity: moderate`).

*Exclusions: Certificates for domains in `known_own_domains` match no rules and never alert.*

---

## 5. Comprehensive Proof Test Matrix

All tests must pass against Postgres and Redis test fixtures. Zero existing tests may be modified.

| ID | Test Name | Invariant / Specification Verified |
|---|---|---|
| **T1** | `test_fast_screen_latency_warm` | p95 $< 50$ ms across 45 corpus URLs with loopback Redis. |
| **T2** | `test_fast_screen_urlhaus_exact_match_blocks` | Exact URLhaus match returns `block`, `confidence: "high"`. |
| **T3** | `test_fast_screen_brand_typosquat_warns` | Brand impersonation finding returns `warn`, `confidence: "medium"`. |
| **T4** | `test_fast_screen_clean_url_no_local_signals` | Clean URL returns `no_local_signals`, `confidence: "low"`. |
| **T5** | `test_fast_screen_weak_only_no_local_signals` | URL with weak-only findings returns `no_local_signals` (D2 fix). |
| **T6** | `test_fast_screen_redis_down_graceful` | When Redis is unavailable, returns `no_local_signals`, `coverage.completed = 3`. |
| **T7** | `test_fast_screen_coverage_metadata` | Verifies `coverage` object has `completed: 4, planned: 10, scope: "local_pre_screen"`. |
| **T8** | `test_fast_screen_host_only_mode` | `mode: "host_only"` processes domain without full path/query; skips exact URLhaus. |
| **T9** | `test_migration_002_applies_cleanly` | Verifies `002_monitoring.sql` creates all tables, columns, and foreign keys. |
| **T10**| `test_create_api_key_script_stores_hash_only` | Confirms raw key is never written to database; stores SHA-256 hash. |
| **T11**| `test_watch_crud_and_quota_limits` | Watch domain CRUD enforces IDNA, eTLD+1 validation, and 20-domain quota. |
| **T12**| `test_watch_rejects_subdomains` | `POST /api/v1/monitor/watch` with `app.example.com` returns HTTP 400. |
| **T13**| `test_alerts_polling_and_lifecycle` | Alert listing, pagination, acknowledge, and dismiss transitions work. |
| **T14**| `test_alerts_trust_issuer_baseline_path` | Acknowledging alert with `trust_issuer: true` inserts issuer into `domain_issuer_baseline`. |
| **T15**| `test_tenant_isolation_watches_and_alerts` | Tenant A cannot view, acknowledge, or dismiss Tenant B's watches or alerts. |
| **T16**| `test_status_endpoint_reports_health` | `GET /api/v1/monitor/status` reports worker health, CT stream state, and scoped counts. |
| **T17**| `test_rate_limiter_two_tier_behavior` | Unauthenticated requests throttled by IP; authenticated requests throttled by key hash. |
| **T18**| `test_cors_extension_regex_allow` | CORS middleware permits `chrome-extension://` 32-char hex origins and `X-API-Key`. |
| **T19**| `test_known_own_domains_exclusion` | Domains in `known_own_domains` excluded from candidate generation and CT rules 2–5. |
| **T20**| `test_candidate_generator_algorithm_and_cap` | Generates expected permutation types and caps output strictly at 500. |
| **T21**| `test_lookalike_first_scan_silent` | First scan populates `lookalike_state` with 0 alerts; sets `lookalike_scanned_at`. |
| **T22**| `test_consolidated_lookalike_single_alert` | Candidate resolving + MX + RDAP $< 30$d fires exactly ONE consolidated `strong` alert. |
| **T23**| `test_lookalike_dual_resolver_safety` | Domain resolving on either `9.9.9.10` or `1.1.1.1` is treated as resolving. |
| **T24**| `test_dns_prober_timeout_and_fallback` | DNS timeout on primary resolver falls back cleanly without hanging. |
| **T25**| `test_wildcard_dns_detection_aborts_safely` | Wildcard UUID match halts probing and marks target `wildcard_dns_detected`. |
| **T26**| `test_manifest_no_placeholders` | Build gate: rejects manifest records containing `<ENTER` or invalid hex. |
| **T27**| `test_build_script_hash_mismatch_rejected` | Loader rejects committed certificate if PEM SHA-256 does not match manifest. |
| **T28**| `test_retroscan_privacy_zero_report_ids` | Alert evidence contains authority, cert hash, and record ID; ZERO report UUIDs. |
| **T29**| `test_retroscan_guards_null_tls_reports` | Retro-scan gracefully skips rows where `report->'tls_reports'` is null. |
| **T30**| `test_retroscan_ipv6_authority_parsing` | Correctly extracts host from `[2001:db8::1]:443` without crashing. |
| **T31**| `test_reprobe_rate_limit_and_concurrency` | Re-probe respects 24h interval, updates `last_probed_at` on failure, respects 2-slot cap. |
| **T32**| `test_live_analysis_hook_creates_alert` | Route-level hook asynchronously creates alert when analysis sees distrusted CA. |
| **T33**| `test_baseline_backfill_retry_and_org_normalization` | crt.sh timeout triggers retry backoff; normalizes Organization (`O`). |
| **T34**| `test_baseline_empty_initial_cert_alert` | Empty baseline triggers `ct.initial_baseline_established` on first seen cert. |
| **T35**| `test_ct_baseline_gate_blocks_alerts` | Own-domain CT issuance emits zero alerts while `baseline_done == false`. |
| **T36**| `test_ct_unrecognized_issuer_alert` | Positive alert when unauthorized CA issues cert for watched domain. |
| **T37**| `test_ct_false_positives_own_subdomain` | `www.yourbank.com` matching baseline issuer emits zero alerts. |
| **T38**| `test_ct_short_brand_no_distance_flood` | Short brand (`sbi`, len 3) matches zero domains via edit distance. |
| **T39**| `test_ct_prefilter_candidate_set_punycode` | Punycode candidate `xn--...` passes pre-filter via candidate set condition. |
| **T40**| `test_ct_brand_in_subdomain_alert` | `yourbank.com.evil.net` fires `ct.brand_in_subdomain_cert` (`strong`). |
| **T41**| `test_ct_combosquat_is_moderate` | `yourbank-login.com` fires `ct.combosquat_cert` (`moderate`). |
| **T42**| `test_ct_san_sanitization_and_caps` | Rejects SANs $>253$ chars, truncates certs $>50$ SANs, strips control chars. |
| **T43**| `test_ct_cross_tenant_dedupe_safety` | Two tenants watching the same domain both receive independent alerts. |
| **T44**| `test_ct_fallback_poller_rule1_scope` | Fallback poller alerts on own-domain unauthorized issuer only. |
| **T45**| `test_worker_advisory_lock_concurrency` | Second worker instance exits cleanly when advisory lock `948201` is held. |
| **T46**| `test_alert_wording_neutral_language` | Asserts alert titles and findings contain no emotive words (malicious, evil). |

---

## 6. Implementation Schedule & Build Order

Total engineering effort: **62.0 hours**.

| Phase | Deliverable | Scope & Tasks | Est. Hours | Done When |
|---|---|---|---|---|
| **Gate 0** | **`tls_reports` Persistence Verification** | Send HTTPS request to `POST /api/v1/analyse/url`, fetch via `GET /api/v1/reports/{id}`, and confirm `tls_reports` is persisted in PostgreSQL JSONB. | 1.0 hr | Integration test asserts `tls_reports` dictionary exists in retrieved PostgreSQL row. |
| **Phase 1** | **Shared Foundation & APIs** | Migration `002_monitoring.sql`, `auth.py`, `limiter.py` (2-tier rate limiting), `routes_watch.py` (CRUD + eTLD+1), `routes_alert.py` (list, ack, dismiss + `trust_issuer`), `routes_status.py`, `worker.py` daemon with Windows Selector loop, advisory lock heartbeat, and multi-task runner. | 14.0 hrs | Migration applies; watch, alert, and status endpoints pass validation, quota, and tenant isolation tests; worker acquires lock; all Phase 1 proof tests pass. |
| **Phase 2** | **Feature A: Fast-Path Screen** | `screen_url` pipeline in `analyser.py`, `POST /api/v1/screen/url` in `routes.py`, `ScreenRequest` union (`mode: "full"` / `"host_only"`), and CORS extension configuration. | 8.0 hrs | Warm p95 $< 50$ ms across 45 corpus URLs; URLhaus exact matches return `block`; clean URLs return `no_local_signals`; Redis-down degrades gracefully. |
| **Phase 3** | **Feature B1: Lookalike Monitoring** | Candidate generator (10 algorithms, 500 cap, `known_own_domains` exclusion), dual unfiltered DNS prober (`9.9.9.10` / `1.1.1.1`) with short-circuiting, consolidated transition alerting engine, and scheduled worker task. | 15.0 hrs | First scan silent; single consolidated alert on resolving+MX; wildcard DNS targets abort safely; MX queried only on resolving. |
| **Phase 4** | **Feature B2: CA Distrust Re-scan** | `test_manifest_no_placeholders` gate, authority-specific retro-scan with zero report UUID leakage, IPv6 parsing, route-level live analysis hook, and 24h active re-probing. | 9.0 hrs | Rejects placeholders; retro-scan matches authorities without leaking report IDs; re-probe respects 24h throttle, updates on failure, respects 2-slot cap. |
| **Phase 5** | **Feature B3: CT Monitoring** | `CTSource` abstraction, `ReplayFixtureCTSource`, `websockets` consumer task in `worker.py`, 4-condition pre-filter, crt.sh backfill with Organization normalization and retry backoff, 5-tier matcher, and crt.sh fallback poller. | 15.0 hrs | crt.sh backfill handles errors and sets `baseline_done`; in-memory filter drops noise; combosquats alert as `moderate`; length buckets prevent short-brand flood; fallback poller operates. |

### Cut Line
1. **Never Cut**: Gate 0 (`tls_reports` persistence verification), Phase 1 (Foundation DDL, auth, watch CRUD, alert APIs, status API, worker locking), Phase 2 (Fast Path), crt.sh baseline backfill with retry, candidate 500 cap, and wildcard DNS guard.
2. **First to Cut (Defer to Post-MVP)**:
   - Live WebSocket Certstream: Run CT monitoring strictly via crt.sh fallback polling.
   - Lookalike RDAP lookups: Restrict transition alerts to DNS A/AAAA and MX records only.
   - Historical CA report re-scan: Restrict distrust matching to live incoming analyses.

---

## 7. Accepted Limitations (Documented System Reality)

### Detection Scope
1. **Local-Only Fast Path**: The `/api/v1/screen/url` endpoint runs local static heuristics and local URLhaus lookups only. It does not perform network redirects, live DNS queries, or TLS certificate verification. A verdict of `no_local_signals` is not a safety claim.
2. **Observable DNS State**: Lookalike monitoring reports observable DNS resolution and record configurations; it does not claim malicious intent.
3. **Detection Latency**: A new lookalike domain can be observed up to 24 hours after DNS activation due to the scheduled polling cadence.
4. **Permutation Boundaries**: Candidate generation produces a maximum of 500 prioritized variations per watched domain. Obscure variations beyond this ceiling are not monitored.
5. **Wildcard DNS Masking**: If a target TLD or parent domain uses wildcard DNS resolution (detected via random UUID queries), candidate DNS probing is skipped to prevent false-positive floods.
6. **Short Brand CT Boundaries**: Brands under 6 characters do not receive fuzzy or edit-distance CT matching to prevent alert flooding on public log streams.

### Certificate Transparency (CT)
7. **Stream Disconnection Gaps**: The live WebSocket stream can experience gaps during disconnects. Historical gaps are not backfilled unless observed via manual replay or fallback polling.
8. **Fallback Scope**: The crt.sh fallback poller covers Rule 1 (own-domain issuance) only. Rules 2–5 are inactive during stream fallback.
9. **Third-Party Availability**: The public Certstream service is operated by a third party with no service-level agreement or availability guarantee.
10. **SCT Verification**: Signed Certificate Timestamp (SCT) cryptographic signatures are not validated.
11. **crt.sh Rate Limits**: crt.sh imposes upstream rate limits, slow responses on large domains, and occasional HTTP 504 gateway timeouts.

### Certificate Authorities (CA)
12. **Dataset Scope**: CA distrust matching covers only explicitly verified records committed to `src/links/data/ca_distrust/manifest.json` (currently 1 verified record: eMudhra BV).
13. **Same-CA Mis-issuance**: A certificate mis-issued by an already-authorized CA organization is invisible to the own-domain issuer baseline.
14. **Apex-Only Re-Probe**: Automated 24-hour CA re-probing checks the apex domain (`watch.domain_ascii:443`). Subdomains (`mail`, `vpn`) are not probed unless explicitly registered.
15. **Known Sibling Exclusion**: Domains listed in `known_own_domains` are completely excluded from monitoring alerts.

### User Privacy
16. **Privacy Boundaries**: Watch owners see the matched hostname, distrust record ID, certificate SHA-256 fingerprint, and timestamp of analyses matching their registered domains, but NEVER the submitted URL, path, query parameters, or report UUID.

### Operations & Maintenance
17. **Single Worker Instance**: The background worker runs as a single daemon with PostgreSQL advisory locking; active-active high availability is not supported.
18. **REST Polling Delivery**: Alerts are retrieved via REST polling endpoints; automated outbound email or webhook delivery is not implemented.
19. **Retention Window**: Monitoring alerts are retained for 90 days, after which they are purged.
20. **Flapping Domain Suppression**: Alerts for a flapping domain (e.g. intermittent DNS failures) are suppressed for the 90-day retention period.
21. **Watch Immutability**: A watch target cannot be edited in place. Changing `known_own_domains` requires deleting and recreating the watch, resetting its state and baseline.
22. **Manual Key Provisioning**: API keys are generated manually via CLI script (`scripts/create_api_key.py`).
23. **IP-Based Fast Path Rate Limiting**: The unauthenticated fast path is rate-limited per remote IP, which may be coarse behind corporate NAT gateways.

---

## 8. Open Items for Team Agreement

1. **Sprint Allocation Decision**: Formally confirm the sprint sequence: execute Mandatory MVP modules (Module 3 AI Explanation, Module 4 Scam Analysis, Module 6 Web3 Registry, and Dashboard) prior to starting the 62.0-hour monitoring suite.
2. **Browser Extension Interface Contract**: Agree on `POST /api/v1/screen/url` payload format and whether client extensions default to `mode: "full"` or privacy-preserving `mode: "host_only"`.
3. **Host Network Egress**: Verify whether production host containers permit outbound HTTPS to `https://crt.sh` and WebSocket traffic to `wss://certstream.calidog.io`. If blocked, CT monitoring will operate in `DEGRADED_NO_EGRESS` mode.
4. **CA Dataset Research Allocation**: Allocate 2–3 research hours to download and verify official CCADB/Mozilla PEMs and serials for DigiNotar and WoSign before committing them to the dataset.

---

## Repository Implementation Status (2026-11-09)

The repository now contains implementation code for the major features in this specification:

- Implemented: migrations `002_monitoring.sql` through `004_ct_poll_cursor.sql`; API-key hashing/authentication and creation CLI; watch CRUD; alert list/ack/dismiss routes; owner-scoped status counts; CORS extension support; direct `websockets>=17.4` dependency; and `/api/v1/screen/url` with `full` and `host_only` modes.
- The fast path runs normalization, lexical and brand checks, plus URLhaus in `full` mode. It does not save submitted URLs. Empty results are `no_local_signals` with low confidence.
- Implemented worker services: advisory lock/heartbeat, task loops, lookalike candidate generation and DNS probing, CA live/retro/re-probe lifecycle, CT stream/replay, crt.sh baseline and retry, CT matching, polling fallback, and retention cleanup.
- Rate limits use an IP tier and a Redis-backed API-key tier; if Redis is down, the key tier falls back to a process-local counter.
- Runtime status: DNS, crt.sh, Certstream, fetcher re-probes, and the worker lifecycle have not been live-integration verified. Reports saved before TLS fingerprints were added cannot be matched by the retro-scan.
- Still outstanding: Gate 0 live TLS persistence round-trip and the v1.4 proof-test matrix.
- `uv lock --offline`, `git diff --check`, compileall, and module import checks completed. The test suite was not run.
