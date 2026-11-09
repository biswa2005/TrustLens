ALTER TABLE watch_domains
    ADD COLUMN IF NOT EXISTS last_ct_polled_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS watch_domains_ct_poll_idx
    ON watch_domains(last_ct_polled_at) WHERE enabled = true AND baseline_done = true;
