-- Monitoring foundation: tenant keys, watches, state, alerts, and CT deduplication.
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active BOOLEAN NOT NULL DEFAULT true
);

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
    wildcard_dns_detected BOOLEAN NOT NULL DEFAULT false,
    last_backfill_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(owner_id, domain_ascii)
);
CREATE INDEX IF NOT EXISTS watch_domains_owner_idx ON watch_domains(owner_id) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS watch_domains_scan_idx ON watch_domains(lookalike_scanned_at) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS watch_domains_backfill_idx ON watch_domains(next_backfill_at) WHERE enabled = true AND baseline_done = false;

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

CREATE TABLE IF NOT EXISTS domain_issuer_baseline (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    watch_id UUID NOT NULL REFERENCES watch_domains(id) ON DELETE CASCADE,
    issuer_org TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(watch_id, issuer_org)
);

CREATE TABLE IF NOT EXISTS monitoring_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id TEXT NOT NULL,
    watch_id UUID REFERENCES watch_domains(id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
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

CREATE TABLE IF NOT EXISTS monitor_state (
    task_name TEXT PRIMARY KEY,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_run_at TIMESTAMPTZ,
    last_error TEXT,
    state JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS ct_seen_certs (
    cert_dedupe_hash TEXT PRIMARY KEY,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ct_seen_certs_seen_at_idx ON ct_seen_certs(seen_at);
