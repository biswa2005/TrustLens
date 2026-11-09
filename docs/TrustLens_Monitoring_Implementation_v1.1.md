# TrustLens: Real-Time Protection and Domain/Certificate Monitoring
## Engineering Implementation Plan v1.1

**Scope:** Real-Time Phishing Pre-Screening (Fast Path), Proactive Lookalike/Homoglyph Monitoring, CA Distrust Intelligence Lifecycle, and Certificate Transparency (CT) Issuance Monitoring.  
**Document Status:** Final Revised Implementation Specification (Plan Only — No Code Modified, No Migrations Run, No Installs).  
**Supersedes:** `docs/TrustLens_Monitoring_Implementation_v1.0.md`.  
**Authoritative Baselines:** `TrustLens_Module2_Implementation_v2.6.md`, `context.md`, `IMPLEMENTATION_CHECKLIST.md`, `src/links/services/analyser.py`, `src/links/services/risk.py`, `src/links/services/registry.py`, `src/links/services/redis_store.py`, and `src/links/services/tls/distrust.py`.

---

## 1. Verified Baseline & Repo Findings (Phase 1)

Every claim in this section is verified against repository source code.

### 1.1 Repository Verification Findings Table

| # | Topic / Question | Verified Implementation in Repository | Exact Evidence (File & Line) | Confidence |
|---|---|---|---|---|
| **1** | **Check Runner & Subsets** | `@register_check(check_id, *, depends_on, timeout, needs_network)` registers specs into `CHECKS: dict[str, CheckSpec]`. `execute()` accepts `list[Finding]` or `(CheckResult, list[Finding])`. `run_all(ctx, order)` takes an explicit check order but **strictly enforces** `order[0] == "normalise"`. Crucially, `intel_urlhaus` has `depends_on=("normalise", "redirect_chain")`. If `redirect_chain` is omitted from `order`, `run_all` raises `ValueError: check dependencies contain a cycle or unknown check`. Therefore, fast-path screening runs `run_all(ctx, ["normalise", "lexical", "brand_impersonation"])` and executes `urlhaus.run(ctx.nurl.normalised)` directly. | `src/links/services/registry.py:34-79`<br>`src/links/services/analyser.py:276`<br>`src/links/models.py:65-69` | High |
| **2** | **Risk Engine & Gating** | `classify(findings, checks)` aggregates findings by evidence group and class. `GATING_CHECKS` is a frozen set of the original 10 Module 1 check IDs. `_ok_gating(checks)` checks only those 10. `risk="low"` **strictly requires** `len(ok) >= 7` AND external reputation OK (`intel_safebrowsing` or `intel_virustotal`). On a 4-check local subset, `len(ok) <= 4` and external reputation is false; `classify()` evaluates to `"inconclusive"` when clean, or `"suspicious"` / `"confirmed_malicious"` when findings fire. It **cannot** evaluate to `"low"`. | `src/links/services/risk.py:4-26` | High |
| **3** | **DL, Confusables, Brands, DNS** | `confusables.is_mixed_script()` and `is_confusable()` detect homoglyphs. `DamerauLevenshtein.distance()` calculates edit distance. `BRANDS` is loaded from `brands.json`. `dns_check(host, registered_domain)` resolves A/AAAA/MX/NS/TXT and returns `(status, findings, reason)`. They are pure detectors; **zero candidate generator exists in the repo**. | `src/links/services/analyser.py:18-19, 50, 108-124`<br>`src/links/services/checks/network.py:10-35` | High |
| **4** | **`tldextract` Network Behavior** | Configured with `_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)`. Empty `suffix_list_urls=()` disables network downloads and forces reliance on the bundled snapshot. **Zero network calls occur on the hot path.** | `src/links/services/checks/normalise.py:9` | High |
| **5** | **URLhaus Redis Lookup API** | `redis_store.lookup(url)` fetches active generation via `r.get("urlhaus:v1:active_generation")` (raises `RuntimeError` if absent). Queries `urlhaus:v1:{gen}:{active|historical}:{url|host}:{sha256}`. `checks/urlhaus.py` catches exceptions and returns `("unavailable", [], str(exc))`. Active exact URL/host matches set `active_confirmation_eligible=True`. If Redis is down, it yields empty findings and unavailable status. | `src/links/services/redis_store.py:26-38`<br>`src/links/services/checks/urlhaus.py:4-12` | High |
| **6** | **Database Migrations** | Startup in `db.open_pool()` checks `schema_migrations` table, reads sorted `src/links/migrations/*.sql`, executes statements split on `;`, and records applied migration. Latest migration is `001_initial.sql`. Uses `UUID PRIMARY KEY`, `TIMESTAMPTZ`, and `JSONB`. | `src/links/services/db.py:17-25`<br>`src/links/migrations/001_initial.sql:1-24` | High |
| **7** | **Auth, Limiter & CORS** | **No API key or user authentication exists** for public routes. `slowapi.Limiter(key_func=get_remote_address)` rate-limits per remote IP (`20/minute` on `/api/v1/analyse/url`). CORS middleware uses `CORS_ALLOW_ORIGINS` (default `http://localhost:3000`). Extensions (`chrome-extension://<id>`) are currently blocked unless explicitly configured in the environment. | `src/links/routes.py:14-18`<br>`src/main.py:42-47` | High |
| **8** | **Process Model & Event Loop** | Host runs FastAPI via `run.py` invoking `runtime.run_uvicorn()`. On Windows (`win32`), `event_loop_factory()` returns `asyncio.SelectorEventLoop` because Uvicorn's default Proactor breaks Psycopg's async pool. Docker Compose runs `fetcher`, `db`, and `redis`. `db.pool` is an `AsyncConnectionPool | None`. **No background task runner or scheduler exists** outside an in-process report purge loop. | `run.py:9-11`<br>`src/links/services/runtime.py:8-24`<br>`src/links/services/db.py:9-14` | High |
| **9** | **Fetcher Models & Guard** | `TLSProbeRequest` has `host`, `port: Literal[443]`, `timeout_budget: float`, `alpn_protocols`. Extra fields are forbidden (`extra="forbid"`). `fetcher/models.py` and `src/links/services/tls/_probe_models.py` are byte-identical. Guard blocks RFC 1918, RFC 4193, loopback, link-local, and non-global IPs. Fetcher has a 4-slot concurrency semaphore (`_tls_sem`). | `src/links/services/tls/_probe_models.py:9-28`<br>`fetcher/guard.py:48-81`<br>`fetcher/app.py:127` | High |
| **10** | **CA Distrust Dataset** | `src/links/data/ca_distrust/manifest.json` contains version `"trustlens-ca-distrust-2026-11-09"` and **exactly 1 verified record** (`em-dv-tls-ca-g3b`, eMudhra BV, classification `"compromised"`). The committed PEM fingerprint matches its manifest expected value; `distrust.py:load_dataset()` accepts it cleanly. `bytes.fromhex()` compares case-insensitively. Extra manifest fields (`source_record`, `retrieved_on`) are safely ignored by the loader. `build_distrust_dataset.py` inspects local files only; **no download logic exists**. Supported scopes: `all` and `leaf_not_before_gte`. | `src/links/data/ca_distrust/manifest.json:1-17`<br>`src/links/services/tls/distrust.py:32-49`<br>`scripts/build_distrust_dataset.py:9-19` | High |
| **11** | **Stored Reports & Re-matching** | `reports` table stores `id UUID`, `submitted_url TEXT`, `report JSONB`, `created_at`, `expires_at`. Retention is 7 days (`REPORT_RETENTION_DAYS`). `tls_reports` is persisted within `report->'tls_reports'`. Certificates contain `fingerprint_sha256` and `spki_sha256` as lowercase hex strings on `leaf_certificate` and `chain_certificates`. Queryable via PostgreSQL JSONB extraction. | `src/links/services/db.py:36-43`<br>`src/links/models.py:129`<br>`src/links/models_tls.py:83-114` | High |
| **12** | **Request Logging & Sanitization** | `routes.py` and `analyser.py` perform **zero request logging of submitted URLs**. `main.py` sanitizes validation errors to generic strings. `reports` table stores raw `submitted_url`. Fast path must not persist URLs or log plaintext navigation streams. | `src/links/routes.py:16-29`<br>`src/main.py:49-51` | High |
| **13** | **Dependencies** | `pyproject.toml` contains `rapidfuzz>=3.11`, `confusable-homoglyphs>=3.3`, `dnspython>=2.7`, `tldextract>=5.1`, `idna>=3.10`, `cryptography>=50.0.2`. `websockets>=17.4` is present transitively via `uvicorn[standard]`, but will be pinned explicitly in `pyproject.toml`. **`certstream` is absent.** | `pyproject.toml:8-26` | High |
| **14** | **Test Assertions on Check Count** | `test_pipeline.py:8` and `test_tls_module2.py:46` assert `len(analyser.CHECK_IDS) == 11` and `CHECK_IDS[-1] == "tls_certificate"`. Adding new check IDs directly to `CHECK_IDS` breaks existing regression tests. Fast-path pre-screening must execute outside `CHECK_IDS`. | `tests/unit/test_pipeline.py:8`<br>`tests/unit/test_tls_module2.py:45-46` | High |
| **15** | **Configuration & Environment** | Configuration is loaded via `dotenv.load_dotenv()` in `run.py` and read via direct `os.environ.get()` calls. `pydantic-settings` is in `pyproject.toml` but `BaseSettings` is not yet implemented across services. | `run.py:6`<br>`src/links/services/db.py:13`<br>`src/links/services/redis_store.py:12` | High |
| **16** | **Current Latency Baseline** | Offline static checks (`normalise`, `lexical`, `brand_impersonation`) process 45 corpus URLs in memory in $<2$ ms per URL (`tests/RESULTS.md`). Redis lookups on loopback take $\sim 1$ ms. Total fast-path in-memory execution is targeted at $< 50$ ms warm. | `tests/RESULTS.md:1-50`<br>`src/links/services/analyser.py:60, 101` | High |

---

### 1.2 Statements in v1.0 Contradicted by Repository Code

1. **`run_all` subset execution**: v1.0 asserted `run_all(ctx, ["normalise", "lexical", "brand_impersonation", "intel_urlhaus"])` can run directly. In reality, `intel_urlhaus` has `depends_on=("normalise", "redirect_chain")` (`analyser.py:276`). Omitting `redirect_chain` causes `run_all` to crash at `registry.py:69` with `ValueError: check dependencies contain a cycle or unknown check`. Fast path must invoke `run_all` on the 3 independent checks and call `urlhaus.run()` directly.
2. **Fast-path verdict mapping**: v1.0 stated "any finding means `warn`". In reality, benign sites regularly trigger weak findings (e.g. `lexical.high_entropy` on student portfolios, as documented in `tests/RESULTS.md:16`). Fast path must call `risk.classify()` and map weak-only results to `no_local_signals`.
3. **CA Distrust Manifest Mock Hashes**: v1.0 hardcoded mock SHA-256 digests for DigiNotar and WoSign. This violates Module 2 Section 13 rules (committed PEMs only with hand-verified hashes from CCADB).
4. **Lookalike First-Scan Behavior**: v1.0 alerted on existing resolving domains on first scan. In reality, existing domains are not new attacks. First scan must record state silently to establish a baseline.
5. **Certstream process model**: v1.0 proposed using the synchronous `certstream` package. The repository is purely async and already has `websockets 17.4` available via Uvicorn.

---

## 2. Fixed Decisions

| # | Decision | Status | Rationale |
|---|---|---|---|
| **D1** | **Check Sequence Independence** | Fixed | Fast-path screening runs `run_all(ctx, ["normalise", "lexical", "brand_impersonation"])` followed by direct `urlhaus.run(ctx.nurl.normalised)`. `CHECK_IDS` (11) and `GATING_CHECKS` (10) remain completely untouched. |
| **D2** | **Risk-Engine-Driven Verdict** | Fixed | Fast path passes findings and check results into `risk.classify()`. Active URLhaus exact/host match gives `block`; `classify()` returning `confirmed_malicious`, `high`, or `suspicious` gives `warn`; anything else gives `no_local_signals`. |
| **D3** | **Unauthenticated Fast Path** | Fixed | `/api/v1/screen/url` is called unauthenticated by browser extensions to avoid leaking user API keys in client extension binaries. Abuse is prevented via dedicated IP rate limiting (`60/minute`). |
| **D4** | **First Scan Silent Baseline** | Fixed | Initial scan of a watched domain populates `lookalike_state` without emitting alerts. Subsequent scans alert strictly on state transitions. |
| **D5** | **Safe Public DNS Probing** | Fixed | Watchlist candidate DNS probing uses host `dnspython` with fixed public recursive resolvers (`9.9.9.9`, `1.1.1.1`), 2.0s timeout, concurrency semaphore (20), and random-UUID wildcard baseline detection. |
| **D6** | **Committed PEM Provenance** | Fixed | No automated certificate download scripts. Distrust records require committed PEMs in `src/links/data/ca_distrust/certs/` with expected hashes entered independently from advisory pages. |
| **D7** | **Retro-Scan Specific Authority Match** | Fixed | Re-scanning historical 7-day reports matches the specific authority whose certificate matched against `watch_domains` across owners. Alerts are created only for the matching owner. Unmatched reports are counted and skipped. Plaintext URLs are never stored in alert evidence. |
| **D8** | **Explicit `websockets` Dependency** | Fixed | Uses async `websockets>=17.4` (explicitly pinned in `pyproject.toml`) inside `worker.py` rather than installing an external synchronous `certstream` package. |
| **D9** | **Single Advisory Lock with Isolated Task Loops** | Fixed | Worker scheduler, backfill tasks, and CT stream run as concurrently isolated tasks inside a single `worker.py` daemon protected by PostgreSQL advisory lock `948201`. Each loop is wrapped in a top-level error handler so a CT crash never halts the scheduler. |
| **D10**| **Watch Model: All Watched Domains Owned** | Fixed | Every domain in `watch_domains` is treated as a protected property owned by the tenant. A `known_own_domains TEXT[]` array stores sibling domains/subdomains. Candidates matching `domain_ascii` or `known_own_domains` are excluded from lookalike alerts and CT Rules 2–5. |
| **D11**| **Mandatory crt.sh Baseline Backfill** | Fixed | Backfill task polls `https://crt.sh/?q=<domain>&output=json` once per watch, populates `domain_issuer_baseline`, and sets `baseline_done = true`. Own-domain issuer alerts remain strictly disabled until `baseline_done` is true. Not subject to cut line. |
| **D12**| **Authenticated Watch Management API** | Fixed | `POST`, `GET`, and `DELETE` `/api/v1/monitor/watch` require `X-API-Key`. Max 20 domains per owner. Full IDNA validation, length cap (253 chars), public suffix check, and IP literal rejection. |

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

-- Watched Domains (All Treated as Owner-Protected Properties)
CREATE TABLE IF NOT EXISTS watch_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id TEXT NOT NULL,
    domain_ascii TEXT NOT NULL,
    domain_display TEXT NOT NULL,
    known_own_domains TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    baseline_done BOOLEAN NOT NULL DEFAULT false,
    last_probed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(owner_id, domain_ascii)
);
CREATE INDEX IF NOT EXISTS watch_domains_owner_idx ON watch_domains(owner_id) WHERE enabled = true;

-- Lookalike State Tracking (Enables Transition-Only Alerting)
CREATE TABLE IF NOT EXISTS lookalike_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    watch_id UUID NOT NULL REFERENCES watch_domains(id) ON DELETE CASCADE,
    candidate_ascii TEXT NOT NULL,
    resolves BOOLEAN NOT NULL,
    has_mx BOOLEAN NOT NULL DEFAULT false,
    rdap_age_days INTEGER,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_checked TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(watch_id, candidate_ascii)
);
CREATE INDEX IF NOT EXISTS lookalike_state_watch_idx ON lookalike_state(watch_id);

-- Own-Domain Authorized CA Issuer Baseline
CREATE TABLE IF NOT EXISTS domain_issuer_baseline (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    watch_id UUID NOT NULL REFERENCES watch_domains(id) ON DELETE CASCADE,
    issuer_dn TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(watch_id, issuer_dn)
);

-- Generic Alert Store
CREATE TABLE IF NOT EXISTS monitoring_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id TEXT NOT NULL,
    kind TEXT NOT NULL, -- 'lookalike_transition' | 'ca_distrust' | 'ct_issuance'
    severity TEXT NOT NULL, -- 'info' | 'weak' | 'moderate' | 'strong'
    status TEXT NOT NULL DEFAULT 'new', -- 'new' | 'acknowledged' | 'dismissed'
    target TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    evidence JSONB NOT NULL,
    source TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at TIMESTAMPTZ,
    limitations JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS monitoring_alerts_owner_status_idx ON monitoring_alerts(owner_id, status);
CREATE INDEX IF NOT EXISTS monitoring_alerts_dedupe_idx ON monitoring_alerts(dedupe_key);

-- Worker Task State and Watermarks
CREATE TABLE IF NOT EXISTS monitor_state (
    task_name TEXT PRIMARY KEY,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_run_at TIMESTAMPTZ,
    last_error TEXT,
    state JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- CT Issuance Deduplication Cache (TTL Managed)
CREATE TABLE IF NOT EXISTS ct_seen_certs (
    cert_dedupe_hash TEXT PRIMARY KEY, -- SHA-256(issuer_dn + serial_hex)
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ct_seen_certs_seen_at_idx ON ct_seen_certs(seen_at);
```

### 3.2 Authentication & Key Management

1. **Authentication Helper (`src/links/services/auth.py`)**:
   - Extracts `X-API-Key` header from incoming administrative requests.
   - Computes `key_hash = hashlib.sha256(api_key.encode()).hexdigest()`.
   - Queries `api_keys` table via `db.pool`. Rejects invalid/inactive keys with HTTP 401.
   - Returns authenticated `owner_id`.
2. **Key Creation Script (`scripts/create_api_key.py`)**:
   - Generates cryptographically secure key: `"tl_live_" + secrets.token_hex(24)`.
   - Computes SHA-256 hash and writes `(key_hash, owner_id, label)` to `api_keys`.
   - Prints the raw key to stdout **exactly once**. Never logs or persists the raw key.
3. **CORS Extension Support (`src/main.py`)**:
   - Updates `CORS_ALLOW_ORIGINS` parsing to allow `chrome-extension://` scheme origins.

### 3.3 Watch Domain Management API (`src/links/routes_watch.py`)

- **`POST /api/v1/monitor/watch`**:
  - Requires `X-API-Key`.
  - Body:
    ```json
    {
      "domain": "example.com",
      "known_own_domains": ["example.net", "example.org"]
    }
    ```
  - Validation:
    - Normalizes domain using `idna.encode(domain.strip().lower(), uts46=True).decode('ascii')`.
    - Rejects IP literals (`ipaddress.ip_address` check).
    - Checks length: FQDN $\le 253$ chars; labels $\le 63$ chars.
    - Public suffix check via `tldextract`: extracted `suffix` must be non-empty and `domain` must be non-empty.
    - Owner quota check: queries count of existing active watches for `owner_id`. If $\ge 20$, returns 400 Bad Request (`"Owner watch limit of 20 domains reached"`).
    - Validates each entry in `known_own_domains` (max 50 sibling domains).
  - Inserts into `watch_domains` with `baseline_done = false`.
  - Schedules immediate lookalike initial baseline scan and crt.sh baseline backfill.
  - Returns 201 Created with created record.
- **`GET /api/v1/monitor/watch`**:
  - Requires `X-API-Key`.
  - Returns `list[WatchDomainResponse]` for the authenticated `owner_id`.
- **`DELETE /api/v1/monitor/watch/{id}`**:
  - Requires `X-API-Key`.
  - Deletes row where `id = %s AND owner_id = %s` (cascades to state and baseline tables).
  - Returns 204 No Content.

### 3.4 Background Worker Process (`worker.py`)

A standalone host daemon executing outside Uvicorn, strictly using `asyncio.SelectorEventLoop` on Windows to preserve Psycopg connection pool stability. Concurrently isolates sub-loops so an error in the CT stream never halts the scheduled task runner.

```python
# worker.py skeleton
import asyncio, sys, os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
sys.path.insert(0, str(ROOT / "src"))

from links.services.runtime import event_loop_factory
from links.services import db

WORKER_LOCK_ID = 948201  # 32-bit advisory lock key

async def safe_loop(coro_fn, name: str):
    """Wrap a long-running async loop so crashes restart after backoff without affecting peers."""
    while True:
        try:
            await coro_fn()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[Worker Error] Loop {name} raised {type(exc).__name__}: {exc}. Restarting in 5s...")
            await asyncio.sleep(5)

async def run_worker_loop():
    await db.open_pool()
    if not db.pool:
        print("Database pool failed to initialize. Exiting.")
        return
    try:
        async with db.pool.connection() as conn:
            res = await (await conn.execute("SELECT pg_try_advisory_lock(%s)", (WORKER_LOCK_ID,))).fetchone()
            if not res or not res[0]:
                print("Another worker instance is holding the advisory lock. Exiting.")
                return

            print("TrustLens background worker acquired lock. Initializing runners...")
            await asyncio.gather(
                safe_loop(scheduled_runner_loop, "scheduler"),
                safe_loop(ct_stream_consumer_loop, "ct_stream")
            )
    finally:
        await db.close_pool()

def main():
    factory = event_loop_factory()
    if factory is None:
        asyncio.run(run_worker_loop())
    else:
        asyncio.run(run_worker_loop(), loop_factory=factory)

if __name__ == "__main__":
    main()
```

### 3.5 Alert Lifecycle & Deduplication Formats

- **Deduplication Key Formats**:
  - Lookalike Transition: `lookalike:{owner_id}:{watch_id}:{candidate_ascii}:{transition_type}`
  - CA Distrust Retro-Scan: `cadistrust:{owner_id}:{matched_authority}:{distrust_version}:{matched_cert_id}`
  - CT Issuance: `ct:{owner_id}:{watch_id}:{issuer_serial_hash}`
- **Alert States**: `new` $\rightarrow$ `acknowledged` $\rightarrow$ `dismissed`.
- **Retention & Meaningfulness**:
  - `monitoring_alerts` retained for 90 days.
  - `reports` retained for 7 days.
  - When a linked report expires, `evidence` in `monitoring_alerts` retains the self-contained snapshot: `target_authority`, `matched_record_id`, `distrust_version`, and `evaluated_at`. The alert remains fully interpretable after the original report is purged.

---

## 4. Feature Specifications

### 4.1 Feature A: Real-Time Phishing Protection (Fast-Path Pre-Screen)

#### Purpose & Scope
Provides an ultra-low-latency pre-screening endpoint for client extensions. Target latency: p95 $< 50$ ms, measured warm over the existing 45-URL corpus with Redis on loopback. Evaluates local normalization, lexical heuristics, brand impersonation, and local Redis URLhaus lookups without outbound network I/O.

#### Pipeline Flow
```
[Client URL] 
     │
     ▼
1. Normalize (normalise.py) ──► Fails? ──► 400 Bad Request
     │
     ▼
2. Run Local Checks (run_all on normalise, lexical, brand_impersonation)
     │
     ▼
3. Run URLhaus Lookup Directly (urlhaus.run on normalised URL)
     │
     ▼
4. Evaluate Findings via risk.classify(findings, checks)
     │
     ├─► Active URLhaus exact/host match? ──────────────────────► VERDICT: "block"
     ├─► classify() in ("confirmed_malicious", "high", "suspicious")? ► VERDICT: "warn"
     └─► Otherwise (clean or weak-only findings)? ──────────────► VERDICT: "no_local_signals"
```

#### API Contract (`POST /api/v1/screen/url`)
- **Authentication**: Unauthenticated (relies on client IP rate limiting: `60/minute`).
- **Request**:
  ```json
  {
    "url": "https://paypa1-security-update.com/login",
    "mode": "full"
  }
  ```
- **Response (`200 OK`)**:
  ```json
  {
    "url_sha256": "4b68ff5c8e2a392b4a53018e69d7a96d1945d7a8d5696c21e7d23589b37c0eb8",
    "verdict": "warn",
    "confidence": "low",
    "coverage": {
      "completed": 4,
      "planned": 10,
      "scope": "local_pre_screen"
    },
    "findings": [
      {
        "id": "brand_impersonation.typosquat",
        "title": "Possible paypal typosquat",
        "severity": "strong"
      }
    ],
    "limitations": [
      "Fast path evaluates local lexical and threat feed indicators only. Absence of indicators does not guarantee safety."
    ],
    "evaluated_at": "2026-11-09T09:40:00Z",
    "elapsed_ms": 3
  }
  ```

#### Performance & Privacy Controls
- **Latency Target**: p95 $< 50$ ms, measured warm with loopback Redis.
- **Privacy Preservation**: URLs are never saved to PostgreSQL or printed in application logs. Logs output only `url_sha256[:16]`.

---

### 4.2 Feature B1: Proactive Lookalike & Homoglyph Monitoring

#### Purpose & Scope
Generates permutation candidates for watched domains, probes active DNS state against independent recursive resolvers, detects state transitions, and surfaces alerts.

#### Candidate Generation Engine (`src/links/services/monitoring/generator.py`)
Generates up to 500 ordered variations using deterministic permutation algorithms:
1. Omission, Transposition, Repetition, QWERTY replacement, Homoglyphs (Cyrillic/Greek via `confusable_homoglyphs`), Hyphenation, Vowel alternation, Bitsquatting, TLD variations, and Combosquatting.
2. Formats all variants to lowercase ASCII punycode (`idna.encode(name, uts46=True).decode('ascii')`).
3. Deduplicates and excludes the watched domain itself and all domains in `known_own_domains`.
4. Caps output strictly at 500 candidates.

#### Safe Public DNS Probing
- Resolver pool: Quad9 (`9.9.9.9`) and Cloudflare (`1.1.1.1`). Concurrency semaphore: 20. Timeout: 2.0s per lookup.
- **Wildcard Detection Baseline**: Queries a 32-character random UUID subdomain (`rand-<uuid>.<tld>`). If it resolves, candidate DNS probing for that target is aborted, marked `wildcard_dns_detected`, and recorded as a limitation.

#### Transition-Only Alerting Matrix
State changes from `lookalike_state` determine alert severity:

| Previous State | Current State | Transition Type | Emitted Severity | Alert Title |
|---|---|---|---|---|
| Not resolving | Resolving | `lookalike_now_resolving` | `info` | Observed active DNS resolution for lookalike domain |
| Not resolving | Resolving + RDAP $< 30$d | `lookalike_recent_registration` | `strong` | Recently registered lookalike domain is now resolving |
| Not resolving | Resolving + Has MX | `lookalike_resolving_with_mx` | `strong` | Lookalike domain is resolving with mail exchange (MX) capability |
| Resolving (No MX) | Resolving (Has MX) | `lookalike_new_mx_record` | `moderate` | Mail exchange records configured for lookalike domain |
| Resolving (RDAP NULL) | Resolving (RDAP $< 30$d) | `lookalike_fresh_registration_confirmed` | `moderate` | Lookalike domain confirmed to be recently registered (age under 30 days) |

*First scan records candidate states silently into `lookalike_state`; zero alerts fire on initial baseline creation.*  
*When RDAP is unavailable or rate-limited, `rdap_age_days` remains `NULL` ("unknown") and is never treated as clean.*

---

### 4.3 Feature B2: CA Distrust Intelligence Lifecycle & Retro-Scan

#### Purpose & Scope
Maintains cryptographic distrust records and executes retroactive audits across stored reports and watched domains whenever the distrust manifest changes.

#### Dataset Maintenance & Expansion Rules
- Manifest file: `src/links/data/ca_distrust/manifest.json`.
- Automated downloading is **strictly prohibited**.
- Verification procedure:
  1. Commit certificate PEM to `src/links/data/ca_distrust/certs/<id>.pem`.
  2. Compute SHA-256 fingerprint in code via `cryptography`.
  3. Compare with `expected_cert_sha256` copied by hand from CCADB or Mozilla/vendor advisories.
  4. Record `source_url`, `source_record`, and `retrieved_on`.

#### Manifest Expansion Specification (Template with Verified eMudhra + Placeholder Records)

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
    },
    {
      "id": "diginotar-root-ca",
      "entity": "DigiNotar Root CA",
      "classification": "compromised",
      "source_url": "https://www.mozilla.org/en-US/security/advisories/mfsa2011-34/",
      "source_record": "<ENTER FROM SOURCE PAGE>",
      "retrieved_on": "<ENTER RETRIEVAL DATE>",
      "cert_file": "certs/diginotar_root_ca.pem",
      "expected_cert_sha256": "<ENTER FROM SOURCE PAGE>",
      "scope": { "type": "all" }
    },
    {
      "id": "wosign-ca-free-ssl-g2",
      "entity": "WoSign CA Free SSL G2",
      "classification": "distrusted",
      "source_url": "https://wiki.mozilla.org/CA:WoSign_Issues",
      "source_record": "<ENTER FROM SOURCE PAGE>",
      "retrieved_on": "<ENTER RETRIEVAL DATE>",
      "cert_file": "certs/wosign_free_ssl_g2.pem",
      "expected_cert_sha256": "<ENTER FROM SOURCE PAGE>",
      "scope": {
        "type": "leaf_not_before_gte",
        "cutoff": "<ENTER CUTOFF FROM SOURCE PAGE>"
      }
    }
  ]
}
```

*Minimum viable dataset count: 3 records (eMudhra + DigiNotar + WoSign). If DigiNotar or WoSign cannot be verified before shipping, the manifest remains at 1 verified record and the build continues without failure.*

#### Retro-Scan Job (`worker.py`)
Triggered when `manifest.version != monitor_state['state']->>'last_distrust_version'`:
1. **Historical Report Scan**:
   - Queries `reports` where `expires_at > now() AND report ? 'tls_reports'`.
   - In Python, iterates over `report['tls_reports'].items()`, extracting `authority_key` and its `leaf_certificate` and `chain_certificates` (`fingerprint_sha256` and `spki_sha256`).
   - If a certificate matches a new distrust record:
     - Extracts `host = authority_key.split(":")[0]`.
     - Extracts registered domain via `tldextract`: `reg_domain = tldextract.extract(host).registered_domain`.
     - Matches against `watch_domains` across all owners where `host == watch.domain_ascii OR host.endswith("." + watch.domain_ascii) OR reg_domain == watch.domain_ascii`.
     - If matched, creates `monitoring_alert` for that owner (`severity: strong`, dedupe key `cadistrust:{owner_id}:{authority_key}:{distrust_version}:{matched_cert_id}`).
     - If unmatched, increments `unmatched_report_matches` telemetry counter and skips alert creation.
2. **Watched Domain Active Re-probe**:
   - Re-probes active `watch_domains` targets where `last_probed_at IS NULL OR last_probed_at < now() - interval '24 hours'`.
   - Sends probe request to fetcher `/probe/tls` with `timeout_budget=8.0`, port 443, supplying `X-Fetcher-Token: os.environ["FETCHER_TOKEN"]`.
   - Concurrency bounded to 2 concurrent probes (leaving 2 slots free on the fetcher's 4-slot semaphore).
   - Result goes through Module 2 distrust matching; if matched, creates alert. Updates `watch_domains SET last_probed_at = now() WHERE id = %s`.

---

### 4.4 Feature B3: Certificate Transparency (CT) Issuance Monitoring

#### Purpose & Scope
Monitors Certificate Transparency logs to alert on unauthorized or lookalike certificate issuance.

#### Baseline Backfill Task (`worker.py`)
For each watch where `baseline_done == false`:
- Queries `https://crt.sh/?q=<domain>&output=json` with a 10s timeout.
- Extracts all unique `issuer_name` strings from active unexpired certificates.
- Inserts each issuer into `domain_issuer_baseline(watch_id, issuer_dn)`.
- Updates `watch_domains SET baseline_done = true WHERE id = %s`.
- Own-domain issuer alerts remain strictly disabled until `baseline_done` is true.

#### Ingestion Architecture (`websockets>=17.4`)
Uses async `websockets` (pinned in `pyproject.toml`) inside `worker.py`:
- Connects to `wss://certstream.calidog.io` (live) or `ReplayFixtureCTSource` (test fixture).
- Queue cap: `asyncio.Queue(maxsize=1000)`. If processing falls behind, oldest entries are dropped and `dropped_stream_records` is incremented.
- Stream gap alert: If no messages arrive for $> 15$ minutes, emits alert `ct.stream_gap` (`info`) and reconnects with exponential backoff.
- Input sanitization: Capped at 253 chars per SAN, 50 SANs per cert. Non-printable characters stripped. Malformed IDNA discarded.

#### Targeted Matching Pipeline (Executed in Strict Priority Order, First Match Wins)
For each normalized SAN (strip `*.`, lowercase, punycode, extract registered domain via `tldextract`):

1. **Own-Domain Rule**:
   - Condition: SAN matches `watch.domain_ascii` or ends with `"." + watch.domain_ascii`.
   - Gate: Alerting is **disabled** until `watch.baseline_done == true`.
   - Logic: If issuer DN is not in `domain_issuer_baseline` $\rightarrow$ Alert `ct.unrecognized_issuer` (`severity: strong`).
   - If SAN contains unexpected wildcard $\rightarrow$ Alert `ct.unexpected_wildcard` (`severity: moderate`).
2. **Exact Candidate Set Match**:
   - Condition: Registered domain exactly matches a candidate in `lookalike_state` $\rightarrow$ Alert `ct.lookalike_cert_issued` (`severity: strong`).
3. **Brand-in-Subdomain**:
   - Condition: Watched brand label appears as a subdomain label while registered domain is different (`yourbank.com.evil.net`) $\rightarrow$ Alert `ct.brand_in_subdomain_cert` (`severity: strong`).
4. **Combosquatting**:
   - Condition: Watched label concatenated with a security keyword (`login`, `verify`, `account`, `secure`) inside registered domain label $\rightarrow$ Alert `ct.combosquat_cert` (`severity: strong`).
5. **Length-Bucket Edit Distance**:
   - Condition: Label length $\ge 6$ with edit distance $\le 1$, or length $\ge 10$ with edit distance $\le 2$ against watched brand label $\rightarrow$ Alert `ct.typosquat_cert` (`severity: moderate`). Labels $< 6$ characters are excluded.

*Owner's domain and all domains in `known_own_domains` are strictly excluded from Rules 2 to 5.*  
*One alert per certificate: because the deduplication key is `ct:{owner_id}:{watch_id}:{issuer_serial_hash}`, the first matching rule generates the alert.*

---

## 5. Interaction with Module 1 and Module 2

1. **Gating Checks Untouched**: `GATING_CHECKS` in `src/links/services/risk.py` **remains strictly the original 10 checks**. Confidence scoring and Low-Risk gating are completely unaffected.
2. **Check ID Registry Untouched**: `CHECK_IDS` in `src/links/services/analyser.py` **remains strictly 11 checks**. Fast-path screening runs outside `CHECK_IDS`.
3. **Zero Test Regressions**: All 472 existing unit tests remain green without modification.

---

## 6. Proof Tests Mapping Table

Every gap and requirement is validated by an offline, deterministic proof test.

| Gap / Requirement | Verification Target | Named Proof Test |
|---|---|---|
| **G1 / M2** | Fast-path verdict never returns `safe` or `low`. Weak-only URL returns `no_local_signals`. | `test_fast_screen_weak_only_returns_no_local_signals` |
| **G2 / M2** | Coverage shows `completed: 4, planned: 10, scope: local_pre_screen`. | `test_fast_screen_coverage_metadata` |
| **G3** | Redis down degrades gracefully to `no_local_signals` with limitation note. | `test_fast_screen_redis_down_graceful_degradation` |
| **G4** | Warm p95 latency target is $< 50$ ms across 45 corpus URLs with zero network calls. | `test_fast_screen_latency_p95_under_budget` |
| **G5** | Unauthenticated access allowed; CORS extension origins permitted; SHA-256 hash logged. | `test_fast_screen_cors_and_hash_logging` |
| **G6** | `mode="host_only"` evaluates host and skips path evaluation. | `test_fast_screen_host_only_mode` |
| **G7** | Generator implements 10 algorithms, caps at 500 variants, outputs ASCII punycode. | `test_lookalike_generator_algorithms_and_cap` |
| **G8** | Dedicated public DNS prober with random-UUID wildcard detection and 2.0s timeout. | `test_dns_prober_wildcard_detection_and_timeout` |
| **G9 / M3** | First scan records state silently. Resolving alone is `info`. Resolving + RDAP $<30$d is `strong`. | `test_lookalike_first_scan_silent`<br>`test_lookalike_resolving_alone_is_info` |
| **G10** | Alert wording uses "observed", "resolving", never "malicious". | `test_lookalike_alert_wording_and_punycode` |
| **G11 / M1** | Build script asserts committed PEM hash matches manifest expected hash. | `test_ca_distrust_build_script_rejects_mismatch` |
| **G12 / M4** | Retro-scan matches authority against owner watches; counts and skips unmatched. | `test_ca_distrust_rescan_owner_matching_and_unmatched_count` |
| **G13 / M1** | Manifest structure test asserts record fields present and rejects mock hashes. | `test_ca_distrust_expanded_dataset_structure` |
| **G14** | Limitation note emitted: URL analysis cannot reveal internal CA key flaws. | `test_ca_distrust_limitation_text_preserved` |
| **G15 / M6** | `www.yourbank.com` not flagged; `yourbank.com.evil.net` flagged; `sbi.in` does not flood. | `test_ct_matcher_avoids_fqdn_false_positives`<br>`test_ct_brand_in_subdomain_alert`<br>`test_ct_label_length_thresholds` |
| **M6** | Combosquat matching generates moderate alert. | `test_ct_combosquat_alert` |
| **G16 / M5** | Own-domain issuer alerts disabled until baseline backfill completed. | `test_ct_baseline_gate_disables_own_domain_alerts` |
| **G17** | Deduplication on `SHA-256(issuer_dn + serial_hex)` prevents duplicate alerts. | `test_ct_deduplication_on_issuer_serial` |
| **G18 / M7** | `CTSource` abstraction tested with offline deterministic replay fixture. | `test_ct_source_replay_fixture_deterministic` |
| **G19 / M7** | Queue drops with counter; stream gap $> 15$ min emits `ct.stream_gap` alert. | `test_ct_stream_queue_drop_and_gap_alert` |
| **G20** | SANs capped at 253 chars, max 50 SANs, control characters stripped. | `test_ct_untrusted_san_sanitization` |
| **G21 / M3** | Migration 002 applies cleanly; `monitoring_alerts`, `lookalike_state`, `watch_domains` created. | `test_monitoring_schema_migration_002` |
| **G22 / M3** | Watch domain management API (`POST`, `GET`, `DELETE`) enforces 20-domain cap and validation. | `test_watch_domain_crud_and_quota_enforcement` |
| **G23 / M7** | Worker acquires advisory lock `948201`; prevents concurrent duplicate runners. | `test_worker_advisory_lock_single_instance` |
| **G24** | Alerts polling endpoint supports status filtering and acknowledgment actions. | `test_alerts_polling_and_ack_endpoints` |
| **G25** | Alert lifecycle transitions: `new` $\rightarrow$ `acknowledged` $\rightarrow$ `dismissed`. | `test_alert_lifecycle_transitions` |
| **M4** | Alert evidence stores host, record ID, and report ID. Never stores `submitted_url`. | `test_alerts_never_store_submitted_url` |
| **M7** | Key creation script `scripts/create_api_key.py` stores SHA-256 hash only. | `test_create_api_key_script_stores_hash_only` |

---

## 7. Implementation Schedule & Build Order

Total engineering effort: **59.0 hours**.

| Phase | Deliverable | Scope & Tasks | Est. Hours | Done When |
|---|---|---|---|---|
| **Phase 1** | **Shared Foundation & Worker** | Migration `002_monitoring.sql`, `auth.py` (`X-API-Key` validation), `routes_watch.py` (CRUD + quota), `scripts/create_api_key.py`, and `worker.py` daemon with Windows Selector loop, advisory lock, and isolated loops. | 12.0 hrs | Migration applies, watch CRUD passes validation/quota, API key script works, worker acquires lock, all Phase 1 tests pass. |
| **Phase 2** | **Feature A: Fast-Path Screen** | Implement `screen_url` in `analyser.py`, `POST /api/v1/screen/url` in `routes.py`, `ScreenRequest`/`ScreenResponse` schemas, and CORS extension configuration. | 8.0 hrs | Target warm p95 $< 50$ ms across 45 corpus URLs; weak findings return `no_local_signals`; URLhaus matches return `block`. |
| **Phase 3** | **Feature B1: Lookalike Monitoring** | Candidate generator (10 algorithms, 500 cap, `known_own_domains` exclusion), public DNS prober with wildcard baseline, transition alerting engine, and scheduled worker task. | 15.0 hrs | First scan silent; resolving transitions alert; wildcard DNS targets abort safely; generator tests pass. |
| **Phase 4** | **Feature B2: CA Distrust Re-scan** | Expand `manifest.json` with verified records, build script verification tests, authority-specific retro-scan worker task, and 24h active re-probing. | 9.0 hrs | Build script rejects mismatch; retro-scan creates alerts for matching authority owners only; unexpired reports matched; re-probe respects 2-slot cap. |
| **Phase 5** | **Feature B3: CT Monitoring** | `CTSource` abstraction, `websockets` consumer task in `worker.py`, `ReplayFixtureCTSource`, targeted 5-tier matcher, and crt.sh baseline backfill task. | 15.0 hrs | crt.sh backfill sets `baseline_done`; replay fixture processes certificates deterministically; subdomains and combosquats alert; own-domain baseline gate works. |

### Cut Line
1. **Never Cut**: Phase 1 (Foundation DDL, auth, watch CRUD, worker locking), Phase 2 (Fast Path), crt.sh baseline backfill task, generator 500 cap, and wildcard DNS baseline guard.
2. **First to Cut (Defer to Post-MVP)**:
   - Live WebSocket Certstream: Run CT monitoring strictly via offline replay fixtures and crt.sh polling.
   - Lookalike RDAP lookups: Restrict transition alerts to DNS A/AAAA and MX records only.
   - Historical CA report re-scan: Restrict distrust matching to new incoming analyses.

---

## 8. Known Limitations (For Repository README)

1. **Pre-Screen Scope**: The `/api/v1/screen/url` endpoint runs local static heuristics and local URLhaus lookups only. It does not perform network redirects, live DNS queries, or TLS certificate verification. A verdict of `no_local_signals` means no local threats were matched; it does **not** guarantee the URL is safe.
2. **Watchlist Permutation Boundaries**: The candidate generator produces a maximum of 500 prioritized variations per watched domain. Highly obscure or multi-word homoglyphs beyond this ceiling are not monitored.
3. **DNS Wildcard Masking**: If a target TLD or parent domain uses wildcard DNS resolution (detected via random UUID queries), candidate DNS probing is aborted for that target to prevent massive false-positive floods.
4. **CT Stream Continuity**: The live Certificate Transparency stream monitors issuance in real-time while connected. If the process is offline or disconnected, historical certificates issued during the gap are not observed unless reconciled via crt.sh backfill.
5. **CA Distrust Provenance**: CA distrust records only match explicitly verified certificates listed in `src/links/data/ca_distrust/manifest.json`. Unlisted compromised private keys or internal PKI defects cannot be detected from public certificates alone.

---

## 9. Open Items for Team Agreement

1. **Browser Extension Interface Contract**: Agree on `POST /api/v1/screen/url` payload format and whether the client extension passes full URLs or enables `mode="host_only"`.
2. **Host Egress for CT & crt.sh**: Confirm whether the host Python environment permits outbound HTTPS to `https://crt.sh` and WebSocket traffic to `wss://certstream.calidog.io` (UNVERIFIED in current environment). If blocked, CT analysis must rely exclusively on offline replay fixtures.
3. **CA Dataset Research Allocation**: Allocate 2–3 research hours to download and verify official CCADB/Mozilla PEMs and serials for DigiNotar and WoSign before committing them to the dataset.
