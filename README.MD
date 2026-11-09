# TrustLens Module 1

TrustLens Module 1 accepts a URL and returns a rule-based risk report. The API runs on the host with Python. Docker Compose runs the isolated fetcher, PostgreSQL 16 with `pgvector`, and Redis 7. Redis is an indicator lookup store, not an analysis check.

## Run locally

1. Copy `.env.example` to `.env` and set `POSTGRES_PASSWORD` and `REDIS_PASSWORD` to the same values used by Compose. Set `DATABASE_URL`, `TEST_DATABASE_URL`, and `REDIS_URL` to the host-published ports in the Compose file (`127.0.0.1:55432` and `127.0.0.1:6379` by default). Keep the test database named `trustlens_test`; integration tests refuse to use a database without a `_test` suffix. Set optional Safe Browsing and VirusTotal API keys if available.
2. Start the supporting services:

   ```powershell
   docker compose up --build -d
   ```

3. Install dependencies and run the API on the host:

   ```powershell
   uv sync --dev
   uv run python run.py
   ```

The API listens on `http://127.0.0.1:8000`. The API is intentionally not a Compose service. PostgreSQL and Redis share a dedicated Compose bridge that the fetcher does not join; their host ports and the fetcher port are loopback-bound for local development. `/healthz` checks PostgreSQL; it returns 503 if PostgreSQL is not configured or unavailable. The fetcher also exposes `/healthz` on port 8001.

On Windows, `run.py` starts Uvicorn's server coroutine with an explicit Selector event loop. This bypasses Uvicorn's default Proactor loop, which Psycopg's async connection pool cannot use.

## Create the database schema

PostgreSQL initializes the `vector` extension on first creation of its data volume. The API applies SQL migrations during startup, including the report, cache, usage-counter, and migration tables. Start PostgreSQL before the API. If a volume was initialized before the init script was added, the migration still creates the extension idempotently.

## Import URLhaus manually

The importer is a one-time setup command. It is never started by the API, a scheduler, or Compose. After Redis is running and the local `REDIS_URL` is configured, run:

```powershell
uv run python scripts/import_urlhaus.py
```

By default, this reads `data/feeds/urlhaus.csv`. To use another local dump, pass its path directly; no container mount is needed because the importer runs on the host:

```powershell
uv run python scripts/import_urlhaus.py --file "C:\path\to\urlhaus.csv"
```

The importer validates and stages a new Redis generation, then switches the active-generation pointer only after a complete successful import. Active and historical records remain separate. Do not submit scanned URLs to URLhaus; analysis performs local Redis lookups only.

## API

- `GET /`, `GET /health`, `GET /healthz`
- `POST /api/v1/analyse/url`, for example:

  ```json
  { "url": "https://example.com", "skip_third_party_reputation": false }
  ```

- `GET /api/v1/reports/{report_id}` retrieves a persisted report until its configured retention period expires.

There are eleven registered checks: `normalise`, `lexical`, `brand_impersonation`, `redirect_chain`, `password_form`, `dns`, `rdap`, `intel_safebrowsing`, `intel_virustotal`, `intel_urlhaus`, and `tls_certificate`. TLS adds evidence and report details, but the original ten checks remain the confidence and Low-Risk coverage gates. Skipping third-party reputation skips Safe Browsing and VirusTotal; it does not skip URLhaus.

For HTTPS on port 443, `tls_certificate` asks the isolated fetcher to perform a bounded TLS handshake and returns certificate, hostname, public trust-store, and configuration findings. The host and fetcher share `FETCHER_TOKEN`; configure the same long random value in `.env` and recreate the fetcher after changing it. The fetcher holds this one access token and has no access to database or Redis credentials. The probe uses `VERIFY_NONE` only behind the fetcher's public-IP guard; ordinary page fetching continues to verify certificates.

## Risk and evidence rules

Risk is based on grouped independent evidence, not a numeric score. Safe Browsing exact URL/host matches, active URLhaus exact URL/host matches, and VirusTotal URL/host reports with at least five malicious engines after excluding Google Safe Browsing can confirm maliciousness. Historical URLhaus evidence cannot confirm; VirusTotal registered-domain evidence is capped at Moderate. Strong evidence from independent classes is required for High Risk. Low Risk requires at least seven successful checks and at least one successful external reputation source; a local feed miss is not proof of safety.

## Verification status and scope

See [IMPLEMENTATION_CHECKLIST.md](IMPLEMENTATION_CHECKLIST.md) and [context.md](context.md) for component-by-component status and the latest recorded test evidence. `docker compose config --quiet` passes. The current fetcher image was rebuilt from the working tree and passed isolation checks on 2026-11-09: PID 1 runs as UID 10001 with `CapEff=0`, no Docker socket, private/DB/Redis connections fail, IPv6 egress is unreachable, and loopback health returns 200. PostgreSQL and Redis report healthy with loopback ports 55432 and 6379 published; a real URLhaus import and active/historical lookups were verified. The latest recorded full suite reported 472 passed, 1 skipped, and 2 warnings; the PostgreSQL integration test was separately run against the configured disposable `_test` database and passed. A current-code API POST returned 200, but its response body and GET-by-ID persistence have not yet been verified.

TLS scope and limitations: only port 443 is probed; IPv6-only authorities currently fail closed because the probe reconstructs a bracketless URL before the SSRF guard, so they produce no certificate evidence; OCSP uses authenticated direct-issuer staples only, with active OCSP, delegated responders, and CRLs out of scope; CT checks parse embedded SCT structure only, with SCT signature validation and log monitoring out of scope; CA distrust matches use only verified records shipped in `src/links/data/ca_distrust/` (the versioned dataset currently contains one Mozilla-documented compromised eMudhra intermediate); and the certifi bundle may differ from a browser or OS trust store. `valid` means the certificate chain and hostname passed these checks; it does not mean the website is safe. The small distrust dataset is not comprehensive CA coverage.

Other limitations include static HTML/redirect inspection, a curated brand list, provider quotas, incomplete corpora, and no full differential browser-parser oracle. Module 5, dashboard/frontend work, embeddings, and LLM explanations remain outside this implementation scope.
