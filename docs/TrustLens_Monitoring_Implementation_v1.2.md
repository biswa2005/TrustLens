# TrustLens: Real-Time Protection and Domain/Certificate Monitoring
## Engineering Implementation Plan v1.2

**Scope:** Real-Time Phishing Pre-Screening (Fast Path), Proactive Lookalike/Homoglyph Monitoring, CA Distrust Intelligence Lifecycle, and Certificate Transparency (CT) Issuance Monitoring.  
**Document Status:** Final Verified Implementation Specification (Plan Only — No Code Modified, No Migrations Run, No Installs).  
**Supersedes:** `docs/TrustLens_Monitoring_Implementation_v1.1.md` and `v1.0.md`.  
**Authoritative Baselines:** `TrustLens_Module2_Implementation_v2.6.md`, `context.md`, `IMPLEMENTATION_CHECKLIST.md`, `src/links/services/analyser.py`, `src/links/services/risk.py`, `src/links/services/registry.py`, `src/links/services/redis_store.py`, and `src/links/services/tls/distrust.py`.

---

## 0. Plan Invariants & Non-Negotiable Boundaries

1. **Safety Over Confidence**: Absence of indicators is never proof of safety. A pre-screen returning zero findings evaluates to `no_local_signals` or `inconclusive`, never `safe` or `low`.
2. **Fixed Engine Gates**: `GATING_CHECKS` remains the original 10 checks in `src/links/services/risk.py:21`. `CHECK_IDS` remains 11 in `src/links/services/analyser.py:47`. New monitoring features do not alter the core analysis pipeline definitions.
3. **Neutral Terminology**: Alerts and findings describe observable state ("resolving", "recently registered", "unrecognized issuer"), never speculative intent ("malicious", "evil").
4. **Tenant Isolation & Strict Privacy**: Alert evidence and responses NEVER store or expose report UUIDs, submitted user URLs, or cross-tenant data. One tenant can never view, acknowledge, or dismiss another tenant's watches or alerts.
5. **Committed Cryptographic Provenance**: Distrust dataset updates require verified certificates committed to the repository. Manifest placeholders (e.g. `<ENTER... >`) are strictly rejected by test gates.

---

## 1. Verified Baseline & Repo Findings (Phase 1)

Every assertion in this section is verified against repository source code.

### 1.1 Repository Verification Findings Table

| # | Topic / Question | Verified Implementation in Repository | Exact Evidence (File & Line) | Confidence |
|---|---|---|---|---|
| **1** | **Check Runner & Subsets** | `@register_check(check_id, *, depends_on, timeout, needs_network)` registers specs into `CHECKS: dict[str, CheckSpec]`. `run_all(ctx, order)` enforces dependencies. `intel_urlhaus` has `depends_on=("normalise", "redirect_chain")`. If `redirect_chain` is omitted from `order`, `run_all` raises `ValueError`. Therefore, fast-path screening runs `run_all(ctx, ["normalise", "lexical", "brand_impersonation"])` and executes `urlhaus.run(ctx.nurl.normalised)` directly. | `src/links/services/registry.py:34-79`<br>`src/links/services/analyser.py:276`<br>`src/links/models.py:65-69` | High |
| **2** | **Risk Engine & Gating** | `classify(findings, checks)` aggregates findings by evidence group. `risk="low"` strictly requires `len(ok) >= 7` AND external reputation OK. On a 4-check local subset, `len(ok) <= 4` and external reputation is false; `classify()` evaluates to `"inconclusive"` when clean, or `"suspicious"` / `"confirmed_malicious"` when findings fire. It cannot evaluate to `"low"`. | `src/links/services/risk.py:4-26` | High |
| **3** | **DL, Confusables, Brands, DNS** | `confusables.is_mixed_script()` and `is_confusable()` detect homoglyphs. `DamerauLevenshtein.distance()` calculates edit distance. `dns_check(host, registered_domain)` resolves A/AAAA/MX/NS/TXT. They are detectors; **zero candidate generator exists in the repo**. | `src/links/services/analyser.py:18-19, 50, 108-124`<br>`src/links/services/checks/network.py:10-35` | High |
| **4** | **`tldextract` Network Behavior** | Configured with `_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)`. Empty `suffix_list_urls=()` disables network downloads. Zero network calls occur on the hot path. | `src/links/services/checks/normalise.py:9` | High |
| **5** | **URLhaus Redis Lookup API** | `redis_store.lookup(url)` fetches active generation via `r.get("urlhaus:v1:active_generation")`. Queries `urlhaus:v1:{gen}:{active|historical}:{url|host}:{sha256}`. Active exact URL/host matches set `active_confirmation_eligible=True`. If Redis is down, it yields empty findings and unavailable status. | `src/links/services/redis_store.py:26-38`<br>`src/links/services/checks/urlhaus.py:4-12` | High |
| **6** | **Database Migrations** | Startup in `db.open_pool()` checks `schema_migrations`, reads sorted `src/links/migrations/*.sql`, and executes statements split on `;`. Latest migration is `001_initial.sql`. Uses `UUID PRIMARY KEY`, `TIMESTAMPTZ`, and `JSONB`. | `src/links/services/db.py:17-25`<br>`src/links/migrations/001_initial.sql:1-24` | High |
| **7** | **Auth & Rate Limiting** | No user authentication currently exists for public routes. `slowapi.Limiter(key_func=get_remote_address)` rate-limits per remote IP (`20/minute` on `/api/v1/analyse/url`). Monitoring routes require API key authentication and independent rate limiting (`60/minute`). | `src/links/routes.py:12-25` | High |
| **8** | **CA Distrust Dataset** | Loaded via `load_dataset()` in `src/links/services/tls/distrust.py:42-72`. Validates committed PEM SHA-256 against `manifest.json`. Current repo manifest has 1 record: `em-dv-tls-ca-g3b` (eMudhra BV, SHA-256 `42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493`, Bugzilla 2083449). `load_dataset` accepts any classification string; `analyser.py:391` checks `r.classification == "compromised"` else defaults to `D.DISTRUSTED`. `bytes.fromhex()` handles uppercase and lowercase hex. | `src/links/services/tls/distrust.py:42-72`<br>`src/links/data/ca_distrust/manifest.json:1-17` | High |
| **9** | **WebSockets Dependency** | `websockets>=17.4` is already installed transitively in the environment via `uvicorn[standard]`. No new PyPI dependency is required for CT ingestion. | `pyproject.toml:23`<br>`uv pip list` | High |

---

## 2. Architectural Decisions (Locked)

| Decision | Topic | Status | Architectural Rule |
|---|---|---|---|
| **D1** | **Fast-Path Check Isolation** | Fixed | Fast path runs `run_all` on `["normalise", "lexical", "brand_impersonation"]` and calls `urlhaus.run()` directly, bypassing `redirect_chain`. |
| **D2** | **Risk Engine Verdict Mapping** | Fixed | Fast path passes the 4 check outputs to `risk.classify()`. Active URLhaus exact/host match yields `block`; Suspicious or higher yields `warn`; anything else yields `no_local_signals`. |
| **D3** | **Dual Unfiltered Resolvers** | Fixed | DNS prober uses unfiltered Quad9 (`9.9.9.10`) and Cloudflare (`1.1.1.1`). If **either** resolver returns an A/AAAA record, the domain is treated as resolving. Resolver disagreement is logged in probe metadata. |
| **D4** | **Silent First Scan & Lookalike Cadence** | Fixed | `lookalike_scanned_at` timestamp on `watch_domains` gates alerting. First scan populates `lookalike_state` silently with 0 alerts. Rescans occur every 24 hours per watch. |
| **D5** | **Consolidated Transition Alerting** | Fixed | One event emits exactly ONE consolidated alert at the highest severity, embedding all observed signals (resolving, MX, RDAP) in its evidence payload. |
| **D6** | **Privacy: Zero Report IDs in Evidence** | Fixed | Alert evidence NEVER contains report UUIDs or raw submitted URLs. Evidence stores `target_authority` (`host:port`), distrust `record_id`, certificate SHA-256 fingerprint, and anonymized timestamp. |
| **D7** | **Template-Only Distrust Manifest** | Fixed | Unverified manifest entries in docs/plans are strictly marked template-only. Build verification tests reject placeholders (`<ENTER... >`) to protect `bytes.fromhex()`. |
| **D8** | **Registered Domain Validation (eTLD+1)** | Fixed | Watch targets must be registered domains (eTLD+1). Subdomains (`app.example.com`) are rejected with HTTP 400. |
| **D9** | **crt.sh Resilient Backfill & Org Normalization** | Fixed | Baseline backfill queries crt.sh once per watch with retry backoff. Normalizes issuer Organization (`O`), avoiding false positives on intermediate rotations. |
| **D10**| **In-Memory CT Pre-Filtering** | Fixed | Public CT stream volume is pre-filtered against an in-memory set of watched domains and lookalike candidates. `ct_seen_certs` records only matching certificates. |
| **D11**| **Authenticated Watch & Alert APIs** | Fixed | Full CRUD for watches and list/ack/dismiss for alerts with tenant isolation (`owner_id`), pagination, and rate limiting (`60/minute`). |
| **D12**| **CT Fallback Polling & Egress Failure Mode** | Fixed | When WebSocket is down, worker polls crt.sh hourly using a watermark. If host egress is completely blocked, CT status is marked `DEGRADED_NO_EGRESS` without halting the worker. |

---

## 3. Shared Foundation Architecture

### 3.1 Migration DDL (`src/links/migrations/002_monitoring.sql`)

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
    lookalike_scanned_at TIMESTAMPTZ,
    last_probed_at TIMESTAMPTZ,
    last_backfill_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(owner_id, domain_ascii)
);
CREATE INDEX IF NOT EXISTS watch_domains_owner_idx ON watch_domains(owner_id) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS watch_domains_scan_idx ON watch_domains(lookalike_scanned_at) WHERE enabled = true;

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

-- Generic Alert Store (dedupe_key UNIQUE creates index automatically)
CREATE TABLE IF NOT EXISTS monitoring_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id TEXT NOT NULL,
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
    cert_dedupe_hash TEXT PRIMARY KEY, -- SHA-256(issuer_org + serial_hex + san_apex)
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ct_seen_certs_seen_at_idx ON ct_seen_certs(seen_at);
```

---

### 3.2 Authentication & Key Management

1. **Authentication Dependency (`src/links/services/auth.py`)**:
   - Extracts `X-API-Key` header from requests.
   - Computes `key_hash = hashlib.sha256(api_key.encode()).hexdigest()`.
   - Queries `api_keys` via `db.pool`. Rejects invalid/inactive keys with HTTP 401.
   - Returns authenticated `owner_id`.
2. **Key Creation Script (`scripts/create_api_key.py`)**:
   - Generates `"tl_live_" + secrets.token_hex(24)`.
   - Computes SHA-256 hash and writes `(key_hash, owner_id, label)` to `api_keys`.
   - Outputs raw key to stdout once. Raw key is never stored.

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
  - Deletes row where `id = %s AND owner_id = %s` (cascades to state and baseline tables). Returns HTTP 204 No Content.

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
  - Acknowledges alert: `UPDATE monitoring_alerts SET status = 'acknowledged', acknowledged_at = now() WHERE id = %s AND owner_id = %s`.
  - Returns HTTP 200 with updated alert, or HTTP 404 if not found or unauthorized.
- **`POST /api/v1/monitor/alerts/{id}/dismiss`**:
  - Request body: `{"reason": "string (optional)"}`.
  - Dismisses alert: `UPDATE monitoring_alerts SET status = 'dismissed', dismiss_reason = %s WHERE id = %s AND owner_id = %s`.
  - Returns HTTP 200 with updated alert, or HTTP 404 if not found or unauthorized.

---

### 3.5 Background Worker Daemon (`worker.py`)

Standalone process executing outside Uvicorn, strictly using `asyncio.SelectorEventLoop` on Windows to preserve Psycopg connection pool stability. Concurrently isolates sub-loops under advisory lock `948201`.

```python
# worker.py loop architecture
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
                safe_loop(watch_scheduler_loop, "scheduler"),
                safe_loop(ct_stream_consumer_loop, "ct_stream"),
                safe_loop(maintenance_purge_loop, "maintenance")
            )
    finally:
        await db.close_pool()
```

#### Scheduler Cadence & Polling Logic (`watch_scheduler_loop`)
The worker polls the database on a 60-second cycle:
1. **Initial Backfill**: `SELECT * FROM watch_domains WHERE enabled = true AND baseline_done = false LIMIT 5`. Runs crt.sh backfill.
2. **Initial Lookalike Baseline**: `SELECT * FROM watch_domains WHERE enabled = true AND lookalike_scanned_at IS NULL LIMIT 2`. Runs silent first scan.
3. **Periodic Lookalike Rescan**: `SELECT * FROM watch_domains WHERE enabled = true AND lookalike_scanned_at < now() - interval '24 hours' ORDER BY lookalike_scanned_at LIMIT 2`. Runs transition scan.
4. **Distrust Manifest Re-Scan**: Checks if manifest version changed in `monitor_state`. If changed, executes retro-scan.
5. **Active Re-Probe**: Re-probes watched domains where `last_probed_at < now() - interval '24 hours' LIMIT 2`.
6. **Retention Purge (`maintenance_purge_loop`)**: Runs daily at 03:00 UTC. Deletes `monitoring_alerts` older than 90 days and `ct_seen_certs` older than 30 days.

---

## 4. Feature Specifications

### 4.1 Feature A: Real-Time Phishing Protection (Fast-Path Pre-Screen)

#### Pipeline Flow
1. **Normalize**: `normalise.py`. Fails $\rightarrow$ HTTP 400.
2. **Local Checks**: `run_all(ctx, ["normalise", "lexical", "brand_impersonation"])`.
3. **URLhaus Redis Lookup**: `urlhaus.run(ctx.nurl.normalised)`.
4. **Risk Engine Classification**: Passes the 4 check outputs to `risk.classify(findings, checks)`.
   - Active URLhaus exact or host match $\rightarrow$ VERDICT: `"block"`.
   - `risk.classify()` in `("confirmed_malicious", "high", "suspicious")` $\rightarrow$ VERDICT: `"warn"`.
   - Otherwise $\rightarrow$ VERDICT: `"no_local_signals"`.

#### API Contract (`POST /api/v1/screen/url`)
- **Authentication**: Unauthenticated (relies on client IP rate limiting: `60/minute`).
- **Request**: `{"url": "https://paypa1-security-update.com/login"}`.
- **Response (`200 OK`)**:
  ```json
  {
    "url_sha256": "4b68ff5c8e2a392b4a53018e69d7a96d1945d7a8d5696c21e7d23589b37c0eb8",
    "verdict": "warn",
    "confidence": "low",
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

---

### 4.2 Feature B1: Proactive Lookalike & Homoglyph Monitoring

#### Candidate Generation Engine (`src/links/services/monitoring/generator.py`)
Generates up to 500 ordered variations using deterministic permutation algorithms (omission, transposition, homoglyphs via `confusable_homoglyphs`, hyphenation, bitsquatting, combosquatting).
- Formats variants to lowercase ASCII punycode via `idna.encode()`.
- **Strict Exclusions**: Excludes `watch.domain_ascii` and all domains in `watch.known_own_domains`.
- Output capped strictly at 500 candidates.

#### Safe Public DNS Probing
- **Dual Unfiltered Resolvers**: Queries Quad9 unfiltered (`9.9.9.10`) and Cloudflare (`1.1.1.1`).
- **Resolution Safety Principle**: If **either** resolver returns an A or AAAA record, the candidate domain is treated as **resolving**. Resolver disagreement is logged in probe metadata.
- Concurrency semaphore: 20. Timeout: 2.0s per lookup. Rate limit: $\le 10$ queries/second.
- **Wildcard Detection Baseline**: Queries `rand-<uuid>.<tld>`. If it resolves, probing is aborted and target marked `wildcard_dns_detected`.

#### Consolidated Transition-Only Alerting Matrix
Only state transitions from `lookalike_state` emit alerts. **Exactly ONE consolidated alert is emitted per candidate evaluation at the highest severity.**

| Transition Scenario | Highest Severity | Consolidated Alert Type | Evidence Payload Contents |
|---|---|---|---|
| Resolving + MX and/or RDAP $< 30$d (Seen on first change) | `strong` | `lookalike_active_threat_indicator` | `{resolves: true, has_mx: true, mx_host: "...", rdap_age_days: 12}` |
| Resolving (No MX, RDAP $\ge 30$d or unknown) | `info` | `lookalike_now_resolving` | `{resolves: true, has_mx: false, rdap_age_days: null}` |
| Already resolving domain: MX record added | `moderate` | `lookalike_new_mx_record` | `{resolves: true, has_mx: true, mx_host: "..."}` |
| Already resolving domain: RDAP confirmed $< 30$d | `strong` | `lookalike_recent_registration_confirmed` | `{resolves: true, rdap_age_days: 14}` |
| Already resolving domain: MX provider changed | `moderate` | `lookalike_mx_provider_changed` | `{old_mx: "...", new_mx: "..."}` |

- **Silent First Scan**: When `lookalike_scanned_at IS NULL`, candidate states are recorded in `lookalike_state` and `lookalike_scanned_at` is set to `now()`. Zero alerts fire.
- **Flapping Protection**: Dedupe key format: `lookalike:{owner_id}:{watch_id}:{candidate_ascii}:{highest_transition_type}`. If a domain flaps between resolving and non-resolving, duplicate alerts are suppressed.
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

#### Retro-Scan Job (`worker.py`)
Triggered when `manifest.version != monitor_state['state']->>'last_distrust_version'`:
1. **Historical Report Scan**:
   - Queries unexpired reports: `SELECT * FROM reports WHERE expires_at > now() AND report ? 'tls_reports'`.
   - Iterates `report['tls_reports'].items()`, extracting `authority_key` (`host:port`).
   - Parses host safely for IPv4 and IPv6:
     ```python
     host = authority_key.rsplit(":", 1)[0].strip("[]")
     ```
   - Matches against newly distrusted certificates in leaf or chain.
   - If matched: matches `host` against `watch_domains` across all owners.
   - **Privacy Protection**: Alert evidence **NEVER stores report UUID or submitted URL**.
     - Evidence payload: `{"matched_authority": authority_key, "distrust_record_id": record.id, "fingerprint_sha256": fp_hex, "distrust_version": manifest.version, "observed_at": report["created_at"]}`.
     - Creates alert for the matching owner only (`severity: strong`, dedupe key `cadistrust:{owner_id}:{authority_key}:{distrust_version}:{record_id}`).
2. **Active Re-Probe**:
   - Re-probes apex `watch_domains` targets where `last_probed_at IS NULL OR last_probed_at < now() - interval '24 hours'`.
   - Bounded to 2 concurrent probes (leaving 2 slots free on fetcher's 4-slot semaphore).
   - Limitation: Apex only (`domain_ascii:443`). Subdomains (`www`, `mail`) are not probed.
3. **Live Analysis Integration**:
   - If a live URL check (`/api/v1/analyse/url`) detects a distrusted CA on a target hostname that matches a registered watch domain, the API process asynchronously inserts a `monitoring_alert` for the watch owner, ensuring real-time alerting without waiting for the next re-probe cycle.

---

### 4.4 Feature B3: Certificate Transparency (CT) Issuance Monitoring

#### Baseline Backfill Task (`worker.py`)
For each watch where `baseline_done == false`:
- Queries `https://crt.sh/?q=<domain>&output=json` with a 15s timeout.
- On timeout, HTTP error, or JSON failure: records `last_backfill_error`, leaves `baseline_done = false`, schedules retry with exponential backoff (5m, 15m, 1h, max 6h). CT Rule 1 remains dormant.
- If crt.sh returns `[]`: marks `baseline_done = true` and `baseline_empty = true`. The first observed CT certificate will establish the initial baseline rather than firing an alert.
- **Organization Normalization**: Normalizes issuer Organization (`O`) into `domain_issuer_baseline`:
  ```python
  norm_org = issuer_attrs.get("O", "").strip().upper()
  ```
  Prevents false positives on CA intermediate rotations (e.g. Let's Encrypt E5/E6/R10/R11).
- Sets `baseline_done = true`.

#### In-Memory Pre-Filtering & Ingestion (`websockets>=17.4`)
1. **In-Memory Pre-Filter**: Compiles a set of watched domain apexes, `known_own_domains`, and lookalike candidates. Certificates whose SANs do not match any monitored domain are **discarded immediately in memory** without database writes.
2. **Deduplication**: `ct_seen_certs` records only matched certificates (`SHA-256(issuer_org + serial_hex + san_apex)`).
3. **Queue Cap & Gap Alert**: `asyncio.Queue(maxsize=1000)`. If stream drops $>15$ minutes, emits `ct.stream_gap` (`info`) and reconnects with exponential backoff.
4. **Fallback Poller**: If WebSocket fails repeatedly, polls `crt.sh/?q=%.{domain}&output=json` hourly using certificate ID watermark (`last_ct_log_id`).
5. **Egress Block Handling**: If host egress is completely blocked to both Certstream and crt.sh, marks `ct_stream_status = 'DEGRADED_NO_EGRESS'` in `monitor_state` and surfaces limitation via status API.

#### Targeted Matching Pipeline (Strict Priority Order, First Match Wins)
For each normalized SAN:
1. **Own-Domain Rule**:
   - SAN matches `watch.domain_ascii` or ends with `"." + watch.domain_ascii`.
   - Gate: Alerting disabled until `watch.baseline_done == true`.
   - If issuer `norm_org` is not in `domain_issuer_baseline` $\rightarrow$ Alert `ct.unrecognized_issuer` (`severity: strong`).
   *(Note: Wildcard checks are dropped from Rule 1 to eliminate false positives).*
2. **Exact Candidate Set Match**:
   - Registered domain matches a candidate in `lookalike_state` $\rightarrow$ Alert `ct.lookalike_cert_issued` (`severity: strong`).
3. **Brand-in-Subdomain**:
   - Watched brand appears as a subdomain label while registered domain differs (`yourbank.com.evil.net`) $\rightarrow$ Alert `ct.brand_in_subdomain_cert` (`severity: strong`).
4. **Combosquatting**:
   - Watched label concatenated with security keyword (`login`, `verify`, `account`, `secure`) inside registered domain label $\rightarrow$ Alert `ct.combosquat_cert` (`severity: moderate`).
5. **Length-Bucket Edit Distance**:
   - Damerau-Levenshtein distance $\le 2$ against watched brand label $\rightarrow$ Alert `ct.similar_name_cert` (`severity: moderate`).

*Exclusions: Certificates for domains in `known_own_domains` match no rules and never alert.*

---

## 5. Comprehensive Proof Test Matrix

All tests must pass against Postgres and Redis test fixtures. Zero existing tests may be modified.

| ID | Test Name | Invariant / Specification Verified |
|---|---|---|
| **T1** | `test_fast_screen_latency_warm` | p95 $< 50$ ms across 45 URLs with loopback Redis. |
| **T2** | `test_fast_screen_urlhaus_exact_match_blocks` | Exact URLhaus match returns `block`, `confidence: "high"`. |
| **T3** | `test_fast_screen_brand_typosquat_warns` | Brand impersonation finding returns `warn`. |
| **T4** | `test_fast_screen_clean_url_no_local_signals` | Clean URL returns `no_local_signals`, `confidence: "low"`. |
| **T5** | `test_watch_crud_and_quota_limits` | Watch domain CRUD enforces IDNA, eTLD+1 validation, and 20-domain quota. |
| **T6** | `test_watch_rejects_subdomains` | `POST /api/v1/monitor/watch` with `app.example.com` returns HTTP 400. |
| **T7** | `test_alerts_polling_and_lifecycle` | Alert listing, pagination, acknowledge, and dismiss transitions work. |
| **T8** | `test_tenant_isolation_watches_and_alerts` | Tenant A cannot view, acknowledge, or dismiss Tenant B's watches or alerts. |
| **T9** | `test_known_own_domains_exclusion` | Domains in `known_own_domains` excluded from candidate generation and CT rules 2–5. |
| **T10**| `test_lookalike_first_scan_silent` | First scan populates `lookalike_state` with 0 alerts; sets `lookalike_scanned_at`. |
| **T11**| `test_consolidated_lookalike_single_alert` | Candidate resolving + MX + RDAP $< 30$d fires exactly ONE consolidated `strong` alert. |
| **T12**| `test_lookalike_dual_resolver_safety` | Domain resolving on either `9.9.9.10` or `1.1.1.1` is treated as resolving. |
| **T13**| `test_wildcard_dns_detection_aborts_safely` | Wildcard UUID match halts probing and marks target `wildcard_dns_detected`. |
| **T14**| `test_manifest_no_placeholders` | Rejects manifest records containing `<ENTER` or invalid hex. |
| **T15**| `test_retroscan_privacy_zero_report_ids` | Alert evidence contains authority, cert hash, and record ID; ZERO report UUIDs. |
| **T16**| `test_retroscan_ipv6_authority_parsing` | Correctly extracts host from `[2001:db8::1]:443` without crashing. |
| **T17**| `test_baseline_backfill_retry_and_org_normalization` | crt.sh timeout triggers retry backoff; normalizes Organization (`O`). |
| **T18**| `test_ct_unrecognized_issuer_alert` | Positive alert when unauthorized CA issues cert for watched domain. |
| **T19**| `test_ct_combosquat_is_moderate` | Combosquatting CT alert emits `moderate` severity. |
| **T20**| `test_ct_in_memory_prefilter_dedupe` | Unrelated certificates discarded in memory without writing to `ct_seen_certs`. |
| **T21**| `test_reprobe_rate_limit_and_concurrency` | Re-probe respects 24h interval and fetcher 2-slot concurrency cap. |
| **T22**| `test_worker_advisory_lock_concurrency` | Second worker instance exits cleanly when advisory lock `948201` is held. |

---

## 6. Implementation Schedule & Build Order

Total engineering effort: **62.0 hours**.

| Phase | Deliverable | Scope & Tasks | Est. Hours | Done When |
|---|---|---|---|---|
| **Phase 1** | **Shared Foundation & APIs** | Migration `002_monitoring.sql`, `auth.py`, `routes_watch.py` (CRUD + eTLD+1 validation), `routes_alert.py` (list, ack, dismiss + tenant isolation), `worker.py` daemon with Windows Selector loop and advisory lock. | 14.0 hrs | Migration applies; watch and alert endpoints pass validation, quota, and tenant isolation tests; worker acquires lock; all Phase 1 proof tests pass. |
| **Phase 2** | **Feature A: Fast-Path Screen** | `screen_url` pipeline in `analyser.py`, `POST /api/v1/screen/url` in `routes.py`, `ScreenRequest`/`ScreenResponse` schemas, and CORS extension configuration. | 8.0 hrs | Warm p95 $< 50$ ms across 45 corpus URLs; URLhaus exact matches return `block`; clean URLs return `no_local_signals`. |
| **Phase 3** | **Feature B1: Lookalike Monitoring** | Candidate generator (10 algorithms, 500 cap, `known_own_domains` exclusion), dual unfiltered DNS prober (`9.9.9.10` / `1.1.1.1`), consolidated transition alerting engine, and scheduled worker task. | 15.0 hrs | First scan silent; single consolidated alert on resolving+MX+RDAP; wildcard DNS targets abort safely. |
| **Phase 4** | **Feature B2: CA Distrust Re-scan** | `test_manifest_no_placeholders` gate, authority-specific retro-scan with zero report UUID leakage, IPv6 parsing, and 24h active re-probing. | 9.0 hrs | Rejects placeholders; retro-scan matches authorities without leaking report IDs; re-probe respects 24h throttle and 2-slot cap. |
| **Phase 5** | **Feature B3: CT Monitoring** | `websockets` consumer task in `worker.py`, in-memory pre-filter, crt.sh backfill with Organization normalization and retry backoff, 5-tier matcher, and crt.sh fallback poller. | 16.0 hrs | crt.sh backfill handles errors and sets `baseline_done`; in-memory filter drops noise; combosquats alert as `moderate`; fallback poller operates. |

### Cut Line
1. **Never Cut**: Phase 1 (Foundation DDL, auth, watch CRUD, alert APIs, worker locking), Phase 2 (Fast Path), crt.sh baseline backfill with retry, candidate 500 cap, and wildcard DNS guard.
2. **First to Cut (Defer to Post-MVP)**:
   - Live WebSocket Certstream: Run CT monitoring strictly via crt.sh fallback polling.
   - Lookalike RDAP lookups: Restrict transition alerts to DNS A/AAAA and MX records only.
   - Historical CA report re-scan: Restrict distrust matching to live incoming analyses.

---

## 7. Known Limitations (For Repository README)

1. **Pre-Screen Scope**: The `/api/v1/screen/url` endpoint runs local static heuristics and local URLhaus lookups only. It does not perform network redirects, live DNS queries, or TLS certificate verification. A verdict of `no_local_signals` means no local threats were matched; it does not guarantee safety.
2. **Watchlist Permutation Boundaries**: The candidate generator produces a maximum of 500 prioritized variations per watched domain. Highly obscure or multi-word homoglyphs beyond this ceiling are not monitored.
3. **DNS Wildcard Masking**: If a target TLD or parent domain uses wildcard DNS resolution (detected via random UUID queries), candidate DNS probing is aborted for that target to prevent false-positive floods.
4. **CT Stream Continuity & Egress Limitations**: The live Certificate Transparency stream monitors issuance in real-time while connected. If outbound WebSocket/HTTPS egress is blocked in the host environment, CT monitoring marks status as `DEGRADED_NO_EGRESS` and must rely on manual log replay.
5. **Re-Probe Covers Apex Only**: Automated 24-hour CA re-probing checks the apex domain (`watch.domain_ascii:443`). Subdomains (e.g. `mail.example.com`, `vpn.example.com`) are not probed unless explicitly added as watched domains.
6. **CA Distrust Provenance**: CA distrust records only match explicitly verified certificates listed in `src/links/data/ca_distrust/manifest.json`. Unlisted compromised private keys or internal PKI defects cannot be detected from public certificates alone.
7. **Lookalike Flapping Suppression**: Lookalike alert deduplication keys suppress repeated alerts for the same candidate transition type within a 30-day window, preventing noise from intermittent DNS failures.
