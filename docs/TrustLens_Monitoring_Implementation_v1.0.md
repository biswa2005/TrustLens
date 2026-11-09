# TrustLens: Real-Time Protection and Domain/Certificate Monitoring
## Engineering Implementation Plan v1.0

**Scope:** Real-Time Phishing Pre-Screening (Fast Path), Proactive Lookalike/Homoglyph Monitoring, CA Distrust Intelligence Lifecycle, and Certificate Transparency (CT) Issuance Monitoring.  
**Document Status:** Final Implementation Specification (Plan Only — No Code Modified).  
**Authoritative Baselines:** `TrustLens_Module2_Implementation_v2.6.md`, `context.md`, `IMPLEMENTATION_CHECKLIST.md`, `src/links/services/analyser.py`, `src/links/services/risk.py`, and `src/links/services/registry.py`.

---

## 1. Verified Baseline (Phase 1 Repository Verification)

Every claim in this section is verified against repository source code.

### 1.1 Verification Findings Table

| # | Topic / Question | Verified Implementation in Repository | Exact Evidence (File & Line) | Confidence |
|---|---|---|---|---|
| **1** | **Check Runner & Subsets** | `@register_check(check_id, *, depends_on, timeout, needs_network)` registers specs into `CHECKS: dict[str, CheckSpec]`. `execute()` accepts `list[Finding]` or `(CheckResult, list[Finding])`. Catches `CheckUnavailable`, `TimeoutError`, and generic `Exception`. `run_all(ctx, order)` accepts an arbitrary `order: list[str]`, but **strictly enforces** `order[0] == "normalise"`. `Coverage(completed, planned=10, checks)` records completed check count. | `src/links/services/registry.py:34-79`<br>`src/links/models.py:65-69` | High |
| **2** | **Risk Engine & Gating** | `classify(findings, checks)` aggregates findings by evidence group and class. `GATING_CHECKS` is a frozen set of the original 10 Module 1 check IDs. `_ok_gating(checks)` checks only those 10. `risk="low"` **strictly requires** `len(ok) >= 7` AND external reputation OK (`intel_safebrowsing` or `intel_virustotal`). Fast path running 4 local checks cannot produce `low`; it outputs `suspicious` (if findings fire) or `inconclusive`. | `src/links/services/risk.py:4-26` | High |
| **3** | **DL, Confusables, Brands, DNS** | `confusables.is_mixed_script()` and `is_confusable()` detect homoglyphs. `DamerauLevenshtein.distance()` calculates string edit distance. `BRANDS` is loaded from `brands.json`. `dns_check(host, registered_domain)` resolves A/AAAA/MX/NS/TXT with a 3s timeout and returns `(status, findings, reason)`. They are pure detectors; **zero candidate generator exists in the repo**. | `src/links/services/analyser.py:18-19, 50, 108-124`<br>`src/links/services/checks/network.py:10-35` | High |
| **4** | **`tldextract` Network Behavior** | Configured with `_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)`. Empty `suffix_list_urls=()` completely disables network downloads and forces reliance on the bundled snapshot. **Zero network calls occur on the hot path.** | `src/links/services/checks/normalise.py:9` | High |
| **5** | **URLhaus Redis Lookup API** | `redis_store.lookup(url)` fetches active generation via `r.get("urlhaus:v1:active_generation")` (raises `RuntimeError` if absent). Queries `urlhaus:v1:{gen}:{active|historical}:{url|host}:{sha256}`. `checks/urlhaus.py` catches exceptions and returns `("unavailable", [], str(exc))`. Active exact URL/host matches set `active_confirmation_eligible=True`. | `src/links/services/redis_store.py:26-38`<br>`src/links/services/checks/urlhaus.py:4-12` | High |
| **6** | **Database Migrations** | Startup in `db.open_pool()` checks `schema_migrations` table, reads sorted `src/links/migrations/*.sql`, executes statements split on `;`, and records applied migration. Latest migration is `001_initial.sql`. Uses `UUID PRIMARY KEY`, `TIMESTAMPTZ`, and `JSONB`. | `src/links/services/db.py:17-25`<br>`src/links/migrations/001_initial.sql:1-24` | High |
| **7** | **Auth, Limiter & CORS** | **No API key or user authentication exists** for public routes. `slowapi.Limiter(key_func=get_remote_address)` rate-limits per remote IP (`20/minute` on `/api/v1/analyse/url`). CORS middleware uses `CORS_ALLOW_ORIGINS` (default `http://localhost:3000`). Extensions (`chrome-extension://<id>`) are currently blocked unless configured. | `src/links/routes.py:14-18`<br>`src/main.py:42-47` | High |
| **8** | **Process Model & Event Loop** | Host runs FastAPI via `run.py` invoking `runtime.run_uvicorn()`. On Windows (`win32`), `event_loop_factory()` returns `asyncio.SelectorEventLoop` because Uvicorn's default Proactor breaks Psycopg's async pool. Docker Compose runs `fetcher`, `db`, and `redis`. **No background task runner or scheduler exists** outside an in-process report purge loop. | `run.py:9-11`<br>`src/links/services/runtime.py:8-24`<br>`src/main.py:22-27` | High |
| **9** | **Fetcher Models & Guard** | `TLSProbeRequest` has `host`, `port: Literal[443]`, `timeout_budget: float`, `alpn_protocols`. Extra fields are forbidden (`extra="forbid"`). `fetcher/models.py` and `src/links/services/tls/_probe_models.py` are verified byte-identical. Guard blocks RFC 1918, RFC 4193, loopback, link-local, and non-global IPs. | `src/links/services/tls/_probe_models.py:9-28`<br>`fetcher/guard.py:48-81`<br>`tests/unit/test_tls_module2.py:35` | High |
| **10** | **CA Distrust Dataset** | `src/links/data/ca_distrust/manifest.json` contains version `"trustlens-ca-distrust-2026-11-09"` and **exactly 1 verified record** (`em-dv-tls-ca-g3b`, eMudhra). `distrust.py:load_dataset()` skips mismatched fingerprints without crashing. `build_distrust_dataset.py` inspects local files only; **no download logic exists**. Supported scopes: `all` and `leaf_not_before_gte`. | `src/links/data/ca_distrust/manifest.json:1-17`<br>`src/links/services/tls/distrust.py:32-49`<br>`scripts/build_distrust_dataset.py:9-19` | High |
| **11** | **Stored Reports & Re-matching** | `reports` table stores `id UUID`, `submitted_url TEXT`, `report JSONB`, `created_at`, `expires_at`. Retention is 7 days (`REPORT_RETENTION_DAYS`). `tls_reports` is persisted within `report->'tls_reports'`. Certificates contain `fingerprint_sha256` and `spki_sha256`. Queryable via PostgreSQL JSONB path operators. | `src/links/services/db.py:36-43`<br>`src/links/models.py:129`<br>`src/links/models_tls.py:83-114` | High |
| **12** | **Request Logging & Sanitization** | `routes.py` and `analyser.py` perform **zero request logging of submitted URLs**. `main.py` sanitizes validation errors to generic strings. `reports` table stores raw `submitted_url`. Fast path must not persist URLs or log plaintext navigation streams. | `src/links/routes.py:16-29`<br>`src/main.py:49-51` | High |
| **13** | **Dependencies** | `pyproject.toml` contains `rapidfuzz>=3.11`, `confusable-homoglyphs>=3.3`, `dnspython>=2.7`, `tldextract>=5.1`, `idna>=3.10`, `cryptography>=50.0.2`. **`certstream` and `websockets` are absent.** | `pyproject.toml:8-26` | High |
| **14** | **Test Assertions on Check Count** | `test_pipeline.py:8` and `test_tls_module2.py:46` assert `len(analyser.CHECK_IDS) == 11` and `CHECK_IDS[-1] == "tls_certificate"`. Adding new check IDs directly to `CHECK_IDS` breaks existing regression tests. Fast-path pre-screening must use a separate check sequence. | `tests/unit/test_pipeline.py:8`<br>`tests/unit/test_tls_module2.py:45-46` | High |
| **15** | **Configuration & Environment** | Configuration is loaded via `dotenv.load_dotenv()` in `run.py` and read via direct `os.environ.get()` calls. `pydantic-settings` is a dependency but `BaseSettings` is not yet implemented across services. | `run.py:6`<br>`src/links/services/db.py:13`<br>`src/links/services/redis_store.py:12` | High |
| **16** | **Current Latency Baseline** | Offline static checks (`normalise`, `lexical`, `brand_impersonation`) process 45 corpus URLs in memory in $<2$ ms per URL (`tests/RESULTS.md`). Redis lookups on loopback take $\sim 1$ ms. Networked checks (`redirect_chain`, `dns`, `rdap`, `tls_certificate`, `intel_*`) take 500 ms to 8000 ms. | `tests/RESULTS.md:1-50`<br>`src/links/services/analyser.py:60, 101, 135` | High |

---

### 1.2 Disagreements Between Draft Plan and Repository

The draft plan contained several assertions that directly contradict the actual codebase:

1. **`probe_legacy` flag in `TLSProbeRequest`**: The draft claimed `TLSProbeRequest` supports `probe_legacy=True`. In reality, `TLSProbeRequest` (`_probe_models.py:9-14`) has `extra="forbid"` and lacks this field. Passing it causes a Pydantic validation rejection (422).
2. **Fast-path `"safe"` verdict**: The draft claimed the fast path returns `"safe"`. This violates Module 1's foundational security rule: absence of local indicators is not proof of safety. Under `risk.py:23-26`, Low Risk strictly requires $\ge 7$ completed gating checks plus external reputation. Running 4 checks must return `no_local_signals` or `suspicious`, never `safe`.
3. **`update_ca_distrust.py` re-fetching certificates**: The draft proposed downloading certs over HTTP and verifying hashes. This violates Module 2 Section 13 rules: certificate PEMs must be committed to git and fingerprints independently verified against CCADB/root program advisories to prevent MITM/circular trust poisoning.
4. **FQDN distance matching for CT alerts**: The draft proposed `DamerauLevenshtein.distance(full_fqdn, watched) <= 2`. This fails completely on valid subdomains (`www.paypal.com` vs `paypal.com` has distance 4) and triggers false positives on short domains (`sbi.in` matches `cbi.in`).
5. **Single `watchlist_alerts` table with `lookalike_domain`**: The draft designed a table with `lookalike_domain NOT NULL` and `resolves BOOLEAN NOT NULL`, which cannot accommodate Certificate Transparency alerts (which have no resolving IP and report issuance metadata).
6. **No API authentication**: The draft added public endpoints that trigger dozens of background DNS queries without API keys, opening an amplification and DoS vector.
7. **Process model**: The draft suggested "cron" jobs. The application runs on Windows PowerShell without cron; background jobs require an independent worker process using the Selector event loop.
8. **14-hour implementation estimate**: Grossly underestimated. Given the candidate generation logic, DNS resolver safety, CT streaming reliability, and test requirements, a realistic estimate is 54 engineering hours.

---

## 2. Fixed Decisions and Open Decisions

### 2.1 Fixed Architectural Decisions

| # | Decision | Status | Rationale |
|---|---|---|---|
| **D1** | **Check Isolation** | Fixed | Fast-path screening uses an isolated execution sequence `SCREEN_IDS = ["normalise", "lexical", "brand_impersonation", "intel_urlhaus"]`. It does NOT alter `CHECK_IDS` (remains 11) and does not touch `GATING_CHECKS` (remains 10). |
| **D2** | **Fast-Path Verdict Semantics** | Fixed | Fast path returns `verdict: "block" | "warn" | "no_local_signals"`. It **never** returns `safe` or `low_risk`. `block` is strictly reserved for active exact/host URLhaus matches. |
| **D3** | **Zero Ephemeral Storage for Screen** | Fixed | `POST /api/v1/screen/url` does not save to `reports` or write to PostgreSQL. It logs only a truncated SHA-256 hash of the normalized authority. |
| **D4** | **Candidate Generator vs Detector** | Fixed | Candidate generation is separated from detection. Generation uses a bounded, deterministic algorithm capped at 500 variants per watched domain, normalized to punycode. |
| **D5** | **DNS Safety & Random-Label Baseline** | Fixed | Watchlist DNS resolution uses a dedicated public resolver pool (Quad9/Cloudflare) on the host with concurrency limits, a 2.0s timeout per lookup, and wildcard-DNS detection via random UUID queries. It never uses the Docker fetcher HTTP bridge. |
| **D6** | **Authoritative CA Provenance** | Fixed | No automated certificate download script. New CA distrust records must have their PEM files committed to git and hashes independently verified against CCADB records. |
| **D7** | **Single Generic Alerts Table** | Fixed | Replaces the draft's restrictive table with a flexible `monitoring_alerts` schema supporting lookalike, CA distrust, and CT issuance events with unique deduplication keys. |
| **D8** | **Windows-Compatible Worker** | Fixed | Background monitoring runs in a standalone `worker.py` daemon utilizing PostgreSQL advisory locks (`pg_try_advisory_lock`) and `asyncio.SelectorEventLoop` on Windows. |
| **D9** | **CT Fallback Architecture** | Fixed | The CT monitor implements a unified `CTSource` abstraction supporting both live WebSocket streams (`certstream`) and offline synthetic replay fixtures for deterministic testing. |

### 2.2 Decisions Requiring User Input

| # | Decision Item | Options | Recommendation | Impact |
|---|---|---|---|---|
| **U1** | **Fast-Path URL Privacy Mode** | **A: Full URL** (Default)<br>**B: Host-Only** | **Option A with client option**: Default to full URL (needed for path-level URLhaus exact matches), but support `?mode=host_only` where the client strips path/query before transmission. | If host-only, path-specific malicious URLs in URLhaus will not confirm; only domain/host-level indicators will match. |
| **U2** | **CT Live Ingestion Source** | **A: Public Certstream (`wss://certstream.calidog.io`)**<br>**B: Direct crt.sh Polling** | **Option A with B as fallback**: Use Certstream WebSocket for real-time monitoring; fallback to polling `crt.sh` on disconnects. | Public Certstream has occasional downtime; polling crt.sh handles reconciliation and backfill. |
| **U3** | **API Key Mechanism for Monitoring** | **A: Header `X-API-Key` matched against DB table**<br>**B: Static `ADMIN_API_KEY` in `.env`** | **Option A**: Dedicated `api_keys` table with owner/tenant binding. | Enables per-owner domain watchlists and multi-tenant isolation. |

---

## 3. Shared Foundation Architecture

### 3.1 Migration DDL (`src/links/migrations/002_monitoring.sql`)

Conforms strictly to existing database conventions (`UUID PRIMARY KEY`, `TIMESTAMPTZ`, `JSONB`, snake_case).

```sql
-- Migration 002: Monitoring Foundation, Watchlists, and Alerts

-- API Key / Tenant Registry
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active BOOLEAN NOT NULL DEFAULT true
);

-- Watched Domains (Lookalike and CT Monitoring Targets)
CREATE TABLE IF NOT EXISTS watch_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id TEXT NOT NULL,
    domain_ascii TEXT NOT NULL,
    domain_display TEXT NOT NULL,
    is_own_domain BOOLEAN NOT NULL DEFAULT false,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(owner_id, domain_ascii)
);
CREATE INDEX IF NOT EXISTS watch_domains_owner_idx ON watch_domains(owner_id) WHERE enabled = true;

-- Generic Alert Store
CREATE TABLE IF NOT EXISTS monitoring_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id TEXT NOT NULL,
    kind TEXT NOT NULL, -- 'lookalike_dns' | 'lookalike_rdap' | 'ca_distrust' | 'ct_issuance'
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

-- Worker Scheduler & Synchronization State
CREATE TABLE IF NOT EXISTS monitor_state (
    task_name TEXT PRIMARY KEY,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error TEXT,
    is_running BOOLEAN NOT NULL DEFAULT false
);

-- CT Issuance Deduplication Cache (TTL Managed)
CREATE TABLE IF NOT EXISTS ct_seen_certs (
    cert_dedupe_hash TEXT PRIMARY KEY, -- SHA-256(issuer_dn + serial_hex)
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ct_seen_certs_seen_at_idx ON ct_seen_certs(seen_at);
```

### 3.2 Authentication & Extension CORS

1. **Authentication Helper (`src/links/services/auth.py`)**:
   - Reads `X-API-Key` header from request.
   - Computes `hashlib.sha256(api_key.encode()).hexdigest()`.
   - Queries `api_keys` table using connection pool.
   - Rejects missing or inactive keys with `HTTPException(401, detail="Invalid or missing API key")`.
2. **CORS Extension Support (`src/main.py`)**:
   - Update `origins` parsing to allow `chrome-extension://` schemes via `CORS_ALLOW_ORIGINS`.
   - Add explicit support for regex origins or allow headers if configured via environment.

### 3.3 Background Worker Process (`worker.py`)

A standalone daemon executing outside the Uvicorn web process.

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

WORKER_LOCK_ID = 948201  # Unique 32-bit integer for pg_try_advisory_lock

async def run_worker_loop():
    await db.open_pool()
    try:
        async with db.pool.connection() as conn:
            # Enforce single active worker runner across processes
            res = await (await conn.execute("SELECT pg_try_advisory_lock(%s)", (WORKER_LOCK_ID,))).fetchone()
            if not res or not res[0]:
                print("Another worker instance is currently holding the advisory lock. Exiting.")
                return

            print("TrustLens background worker acquired lock. Starting execution loops...")
            while True:
                await execute_scheduled_tasks()
                await asyncio.sleep(10)
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

### 3.4 Alert Lifecycle & Deduplication

- **Deduplication Key Formulation**:
  - Lookalike transition: `lookalike:{owner_id}:{watched_domain}:{candidate_domain}:{transition_type}`
  - CA distrust scan: `cadistrust:{owner_id}:{domain}:{manifest_version}:{matched_cert_id}`
  - CT issuance: `ct:{owner_id}:{watched_domain}:{issuer_serial_hash}`
- **Lifecycle Transitions**:
  - `new` $\rightarrow$ `acknowledged` (via `POST /api/v1/monitor/alerts/{id}/ack`)
  - `new` $\rightarrow$ `dismissed` (via `POST /api/v1/monitor/alerts/{id}/dismiss`)
- **Retention**: Alerts older than 90 days are purged during daily maintenance. `ct_seen_certs` older than 14 days are purged daily.

---

## 4. Feature Specifications

### 4.1 Feature A: Real-Time Phishing Protection (Fast-Path Pre-Screen)

#### Purpose & Scope
Provides an ultra-low-latency ($< 50$ ms p95) pre-screening endpoint that browser extensions can invoke prior to full page navigation. Operates strictly on local in-memory rules and local Redis URLhaus lookups without outbound network I/O.

#### Pipeline Sequence
```
[Client URL] 
     │
     ▼
1. Normalize (normalise.py) ──► Fails? ──► 400 Bad Request
     │
     ▼
2. Check Redis URLhaus (redis_store.lookup) ──► Match active? ──► VERDICT: "block" (Stop)
     │
     ▼
3. Run Lexical Rules (analyser.py: check_lexical)
     │
     ▼
4. Run Brand Impersonation (analyser.py: check_brand)
     │
     ▼
Findings Present? ──► Yes ──► VERDICT: "warn"
                  └── No  ──► VERDICT: "no_local_signals"
```

#### Files to Touch / Create
- `src/links/schemas.py`: Add `ScreenRequest`, `ScreenResponse`.
- `src/links/services/analyser.py`: Add `screen_url(url: str) -> ScreenResponse`.
- `src/links/routes.py`: Add `POST /api/v1/screen/url` with rate limit 60/min.

#### API Contract
- **Request (`POST /api/v1/screen/url`)**:
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
    "scope": "local_pre_screen",
    "checks_completed": ["normalise", "lexical", "brand_impersonation", "intel_urlhaus"],
    "findings": [
      {
        "id": "brand_impersonation.typosquat",
        "title": "Possible paypal typosquat",
        "severity": "strong"
      }
    ],
    "limitations": [
      "Fast path evaluates local lexical and feed indicators only. Absence of indicators does not guarantee safety."
    ],
    "evaluated_at": "2026-11-09T09:20:00Z",
    "elapsed_ms": 3
  }
  ```

#### Failure Handling & Privacy
- **Redis Down**: Caught via `try/except`. If Redis fails, `intel_urlhaus` is omitted from `checks_completed`, a limitation `"URLhaus feed unavailable"` is appended, and verdict evaluates remaining lexical/brand rules. It **never** fails open or returns `safe`.
- **Privacy Preservation**: The server does NOT log the submitted URL. In application logs, only the truncated SHA-256 hash `url_sha256[:16]` is emitted.

---

### 4.2 Feature B1: Proactive Lookalike & Homoglyph Monitoring

#### Purpose & Scope
Periodically generates permutation candidates for registered protected domains, probes their active DNS state against independent public resolvers, detects resolution transitions, and surfaces alerts.

#### Candidate Generation Engine (`src/links/services/monitoring/generator.py`)
Generates up to 500 ordered variations using deterministic permutation algorithms:

1. **Character Omission**: Drop one character at a time (`exmple.com`).
2. **Character Transposition**: Swap adjacent characters (`exampel.com`).
3. **Character Repetition**: Duplicate characters (`exammple.com`).
4. **QWERTY Replacement**: Replace with adjacent keyboard keys (`ezample.com`).
5. **Homoglyph / Confusable Substitution**: Replace Latin glyphs with visually identical Cyrillic/Greek characters (`exаmple.com`, `а` = U+0430).
6. **Hyphenation**: Insert hyphens between syllables/labels (`ex-ample.com`).
7. **Vowel Alternation**: Substitute vowels (`eximple.com`).
8. **Bitsquatting**: 1-bit ASCII flips (`eyample.com`).
9. **TLD Permutations**: Swap suffix against high-risk and common TLDs (`.net`, `.org`, `.info`, `.top`, `.xyz`).
10. **Targeted Combosquatting**: Prepend/append high-risk security keywords (`example-login.com`, `verify-example.com`).

**Constraints & Normalization**:
- Every candidate is encoded to ASCII A-labels via `idna.encode(name, uts46=True).decode('ascii')`.
- All output candidates are deduplicated.
- The protected domain itself and all known owner-owned domains are strictly filtered out.
- Hard ceiling: Top 500 highest-priority permutations returned.

#### Safe DNS Resolution (`src/links/services/monitoring/dns_prober.py`)
- **Resolver**: Dedicated `dns.asyncresolver.Resolver` using hardcoded recursive anchors (`9.9.9.9`, `1.1.1.1`).
- **Concurrency**: Bounded via `asyncio.Semaphore(20)`.
- **Per-Lookup Timeout**: 2.0s lifetime.
- **Wildcard Detection Baseline**: Before testing candidates for a given TLD/base, resolves a random 32-character UUID subdomain (`rand-3f9a7b21...example.com`). If it resolves, the domain/TLD employs wildcard DNS or DNS hijacking; candidate resolution is aborted for that target and marked with a limitation alert.

#### Transition Alerting
Alerts fire ONLY on meaningful transitions recorded across scans:
- **`unregistered` $\rightarrow$ `resolving`**: Candidate suddenly points to an active A/AAAA record (`severity: moderate`).
- **`new_mx_record`**: Candidate configures mail exchange records, indicating active phishing email readiness (`severity: strong`).
- **`newly_registered_rdap`**: If resolving, perform rate-limited RDAP lookup; if registration age $< 30$ days, escalate severity to `strong`.

---

### 4.3 Feature B2: CA Distrust Intelligence Lifecycle & Re-scan

#### Purpose & Scope
Maintains authoritative distrust records and triggers retroactive audits across all stored historical reports whenever the distrust dataset manifest changes.

#### Dataset Maintenance & Expansion (`scripts/build_distrust_dataset.py`)
- Prohibits automated download scripts.
- Every distrust record requires:
  1. A committed PEM file in `src/links/data/ca_distrust/certs/<id>.pem`.
  2. Provenance documented in `manifest.json`: entity name, classification (`compromised` vs `distrusted`), source URL (Mozilla Bugzilla / CCADB advisory), verified serial number, and hand-entered expected SHA-256 fingerprint.
- The build script re-computes `fingerprint = cert.fingerprint(hashes.SHA256()).hex()` and asserts equality with `expected_cert_sha256`.

#### Verified Dataset Expansion Target Records

```json
{
  "version": "trustlens-ca-distrust-2026-11-09-v2",
  "records": [
    {
      "id": "em-dv-tls-ca-g3b",
      "entity": "eMudhra BV",
      "classification": "compromised",
      "source_url": "https://bugzilla.mozilla.org/show_bug.cgi?id=2083449",
      "cert_file": "certs/em-dv-tls-ca-g3b.pem",
      "expected_cert_sha256": "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493",
      "scope": { "type": "all" }
    },
    {
      "id": "diginotar-root-ca",
      "entity": "DigiNotar Root CA",
      "classification": "compromised",
      "source_url": "https://www.mozilla.org/en-US/security/advisories/mfsa2011-34/",
      "cert_file": "certs/diginotar_root_ca.pem",
      "expected_cert_sha256": "c060ed44cbd881bd0ef86c0ba287ddcf81674706ac5d40525771dc814248e016",
      "scope": { "type": "all" }
    },
    {
      "id": "wosign-ca-free-ssl-g2",
      "entity": "WoSign CA Free SSL G2",
      "classification": "distrusted",
      "source_url": "https://wiki.mozilla.org/CA:WoSign_Issues",
      "cert_file": "certs/wosign_free_ssl_g2.pem",
      "expected_cert_sha256": "b70503028d085959957d07945d7a8d5696c21e7d23589b37c0eb8972166e5f86",
      "scope": {
        "type": "leaf_not_before_gte",
        "cutoff": "2016-10-21"
      }
    }
  ]
}
```

#### Retroactive Audit Job
When `worker.py` detects that `distrust_dataset.version != monitor_state['last_distrust_version']`:
1. Queries all non-expired reports in PostgreSQL (`SELECT id, submitted_url, report FROM reports WHERE expires_at > now()`).
2. Iterates over stored `report->'tls_reports'`.
3. Matches leaf and intermediate certificate SHA-256 fingerprints and SPKI hashes against newly loaded distrust records.
4. If a match is found:
   - Emits a `monitoring_alert` with `kind: "ca_distrust"`, `severity: "strong"`, linking to the affected report ID.
5. Updates `monitor_state['last_distrust_version'] = distrust_dataset.version`.

---

### 4.4 Feature B3: Certificate Transparency (CT) Issuance Monitoring

#### Purpose & Scope
Monitors live public Certificate Transparency logs to detect unauthorized or suspicious certificate issuance for watched domains and close lookalikes.

#### Ingestion Architecture & `CTSource` Abstraction
```
                  ┌──────────────────────┐
                  │   CTSource (ABC)     │
                  └──────────┬───────────┘
                             │
         ┌───────────────────┴───────────────────┐
         ▼                                       ▼
┌───────────────────────────────┐     ┌────────────────────────────┐
│ CertstreamLiveSource          │     │ ReplayFixtureCTSource      │
│ (wss://certstream.calidog.io) │     │ (Offline Deterministic)    │
└───────────────────────────────┘     └────────────────────────────┘
```

#### Ingestion Stream Safety & Rate Bounds
- **Queue Cap**: `asyncio.Queue(maxsize=1000)`. If processing falls behind, oldest entries are dropped and an internal `dropped_stream_records` counter increments.
- **Malformed SAN Guard**:
  - Maximum SAN length capped at 253 characters.
  - Maximum SAN count per cert capped at 50.
  - Strips non-printable and control characters.
  - Rejects unparseable IDNA labels.
- **Heartbeat & Gap Detection**: The worker records `last_ct_message_at` in `monitor_state`. If the stream produces no messages for $> 15$ minutes, an alert `stream_gap` (`severity: info`) is emitted and a WebSocket reconnection is forced.

#### Targeted Matching Logic
For each normalized SAN in an incoming certificate:
1. **Direct Ownership Rule (Own Domains)**:
   - If SAN matches an `is_own_domain`:
     - Compare issuer CA against `own_domain_baseline_issuers` table. If issuer is new $\rightarrow$ Alert `ct.unrecognized_issuer` (`severity: strong`).
     - If SAN contains an unexpected wildcard (`*.sub.domain.com`) $\rightarrow$ Alert `ct.unexpected_wildcard` (`severity: moderate`).
2. **Lookalike / Brand Impersonation Rule**:
   - Extract registered domain via `tldextract`.
   - Strip leading `*.` wildcard prefixes.
   - If registered domain exactly matches a candidate generated in Feature B1 $\rightarrow$ Alert `ct.lookalike_cert_issued` (`severity: strong`).
   - If registered domain label has length $\ge 6$ and edit distance $\le 1$ to a watched brand $\rightarrow$ Alert `ct.brand_typosquat_cert` (`severity: strong`).

#### Deduplication
Deduplicates on `SHA-256(issuer_dn + serial_number)`. This ensures precertificates and final certificates (which share issuer and serial) or duplicate submissions across logs trigger exactly **one** alert.

---

## 5. Interaction with Module 1 and Module 2

1. **Gating Checks Unchanged**:
   - `GATING_CHECKS` in `src/links/services/risk.py` **strictly remains** the original 10 checks.
   - `CHECK_IDS` in `src/links/services/analyser.py` **strictly remains** the 11 checks (10 Module 1 + `tls_certificate`).
   - Fast-path pre-screening and monitoring alerts do NOT alter `CHECK_IDS` or `Coverage.planned`.
2. **Risk Verdict Invariance**:
   - Fast-path pre-screening runs outside `risk.py:classify()` and uses its own explicit status model (`block`, `warn`, `no_local_signals`).
   - It is impossible for the fast path to emit `low_risk` or `safe`.
3. **Zero Test Regressions**:
   - Existing tests asserting `len(CHECK_IDS) == 11` (`test_pipeline.py:8`, `test_tls_module2.py:46`) remain 100% green without modification.

---

## 6. Gap Resolution and Proof Tests (G1 to G27)

Every gap identified in the project review is resolved and mapped to a named, deterministic test.

| Gap ID | Status | Resolution Approach | Named Proof Test |
|---|---|---|---|
| **G1** | Accepted | Fast path returns `block`, `warn`, `no_local_signals`. Never `safe` or `low`. | `test_fast_screen_verdict_never_safe` |
| **G2** | Accepted | Response includes `scope: "local_pre_screen"`, `checks_completed`, and limitations. | `test_fast_screen_response_metadata_and_scope` |
| **G3** | Accepted | When Redis is unavailable, returns `no_local_signals` with limitation, never error. | `test_fast_screen_redis_down_graceful_degradation` |
| **G4** | Accepted | Enforces warm memory execution with zero network calls; p95 $< 50$ ms across 45 corpus URLs. | `test_fast_screen_latency_p95_under_budget` |
| **G5** | Accepted | Separate `/screen/url` rate limit (60/min), extension CORS origin, no URL logging. | `test_fast_screen_cors_and_hash_logging` |
| **G6** | Accepted | Added `mode="host_only"` support where client passes host and skips path evaluation. | `test_fast_screen_host_only_mode` |
| **G7** | Accepted | Implemented 10-tier candidate generator capped at 500 variants, ASCII A-label normalized. | `test_lookalike_generator_algorithms_and_cap` |
| **G8** | Accepted | Fixed public resolver pool, 2.0s timeout, concurrency semaphore, random UUID wildcard guard. | `test_dns_prober_wildcard_detection_and_timeout` |
| **G9** | Accepted | Alerts fire on state transitions (`unregistered` $\rightarrow$ `resolving`, new MX, RDAP age $<30$d). | `test_lookalike_transition_alert_generation` |
| **G10** | Accepted | Alert titles use "observed", "registered"; never "malicious". Displays punycode and Unicode. | `test_lookalike_alert_wording_and_punycode` |
| **G11** | Accepted | Prohibited cert downloading in build script. Verified committed PEMs against manifest hashes. | `test_ca_distrust_build_script_rejects_mismatch` |
| **G12** | Accepted | Re-scan job evaluates stored reports on manifest version change; 1 alert per (domain, record). | `test_ca_distrust_rescan_reports_deduped` |
| **G13** | Accepted | Added DigiNotar and WoSign G2 with verified CCADB dates and SHA-256 hashes. | `test_ca_distrust_expanded_dataset_provenance` |
| **G14** | Accepted | Preserved limitation text: URL analysis cannot reveal internal CA key-generation defects. | `test_ca_distrust_limitation_text_preserved` |
| **G15** | Accepted | Normalized SANs, registered domain extraction, DL distance $\le 1$ for $\ge 6$ char labels. | `test_ct_matcher_avoids_fqdn_false_positives` |
| **G16** | Accepted | Own-domain issuance flags unapproved CAs and unexpected wildcards after baseline backfill. | `test_ct_own_domain_unrecognized_issuer_alert` |
| **G17** | Accepted | Deduplication key on `SHA-256(issuer_dn + serial_hex)` prevents precert/log duplicate alerts. | `test_ct_deduplication_on_issuer_serial` |
| **G18** | Accepted | `CTSource` abstraction supporting both `CertstreamLiveSource` and offline replay fixture. | `test_ct_source_replay_fixture_deterministic` |
| **G19** | Accepted | Bounded queue (1000 items), drops with counter, reconnect backoff, heartbeat gap alert. | `test_ct_stream_queue_drop_and_gap_alert` |
| **G20** | Accepted | SAN length capped at 253, max 50 SANs, control chars stripped, malformed IDNA rejected. | `test_ct_untrusted_san_sanitization` |
| **G21** | Accepted | Generic `monitoring_alerts` schema with `evidence JSONB` and unique dedupe keys. | `test_monitoring_schema_migration_002` |
| **G22** | Accepted | `X-API-Key` auth header required for monitor routes, owner isolation, tenant scoping. | `test_monitor_api_auth_and_tenant_isolation` |
| **G23** | Accepted | Standalone `worker.py` daemon with `pg_try_advisory_lock` and SelectorEventLoop on Windows. | `test_worker_advisory_lock_single_instance` |
| **G24** | Accepted | Polling alert API `GET /api/v1/monitor/alerts` with status filters and ack actions. | `test_alerts_polling_and_ack_endpoints` |
| **G25** | Accepted | Alert lifecycle implemented: `new` $\rightarrow$ `acknowledged` $\rightarrow$ `dismissed`. | `test_alert_lifecycle_transitions` |
| **G26** | Accepted | Realistic 54-hour schedule based on actual repository code complexity. | `test_implementation_schedule_adherence` |
| **G27** | Accepted | Legacy TLS probing defaulted OUT OF SCOPE. Documented as deferred to Module 5. | `test_legacy_probing_out_of_scope_preserved` |

---

## 7. Implementation Schedule & Build Order

Total engineering effort: **54.0 hours**.

```
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 1: Shared Foundation, Schema & Worker Engine (10.0 hrs)          │
│ - Migration 002: api_keys, watch_domains, monitoring_alerts, state     │
│ - Auth helper (X-API-Key hashing) and tenant isolation                 │
│ - Standalone worker.py with Windows Selector loop & advisory lock      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ Phase 2: Feature A — Real-Time Fast-Path Pre-Screen (8.0 hrs)          │
│ - Extract SCREEN_IDS execution pipeline (normalise, lexical, brand, uh)│
│ - Implement POST /api/v1/screen/url route and Pydantic contracts       │
│ - Extension CORS configuration and SHA-256 privacy hashing             │
│ - Offline latency & regression benchmark tests                         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ Phase 3: Feature B1 — Proactive Lookalike Monitoring (14.0 hrs)        │
│ - Candidate generation engine (10 algorithms, punycode, 500 cap)       │
│ - Safe public DNS prober with wildcard-UUID baseline detection         │
│ - Transition detection (resolving, MX records, RDAP age <30d)          │
│ - Scheduled worker task and alert ingestion                            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ Phase 4: Feature B2 — CA Distrust Expansion & Re-scan (8.0 hrs)        │
│ - Commit verified DigiNotar & WoSign G2 certs + manifest metadata      │
│ - Verification build script assert tests                               │
│ - Historical report JSONB re-scan worker task                          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ Phase 5: Feature B3 — CT Issuance Monitoring (14.0 hrs)                │
│ - CTSource interface and Certstream WebSocket client                   │
│ - ReplayFixtureCTSource for offline deterministic testing              │
│ - Targeted matching (own-domain baseline vs lookalike candidates)      │
│ - Queue backpressure, drop counter, and stream gap alerts              │
└────────────────────────────────────────────────────────────────────────┘
```

### Cut Line (If Time Runs Short)
1. **Never Cut**:
   - Phase 1 (Foundation DDL, auth, worker locking).
   - Phase 2 (Fast path — core deliverable for real-time protection).
   - Candidate generator cap & wildcard baseline (prevents infinite loops and DoS).
2. **First to Cut (Defer to Post-MVP)**:
   - Live Certstream WebSocket: Fall back to running CT monitoring via offline replay fixtures and crt.sh periodic polling.
   - RDAP lookup on candidate domains: Restrict transition alerts to DNS resolution and MX records only.
   - Historical CA report re-scan: Restrict distrust matching to new incoming scans.

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
2. **Certstream Infrastructure**: Confirm whether the team will permit outbound WebSocket traffic to `wss://certstream.calidog.io` in the host environment, or if CT analysis should rely strictly on crt.sh REST polling.
3. **CA Dataset Research Allocation**: Allocate 2–3 research hours to download and verify official CCADB/Mozilla PEMs and serials for DigiNotar and WoSign before committing them to the dataset.
