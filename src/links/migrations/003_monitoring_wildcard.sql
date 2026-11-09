ALTER TABLE watch_domains
    ADD COLUMN IF NOT EXISTS wildcard_dns_detected BOOLEAN NOT NULL DEFAULT false;
