-- Runtime evidence from the dynamic-confirmation pass (Phase 3), linking a scan's
-- static findings/leads to what actually happened on the device.
CREATE TABLE IF NOT EXISTS workflows.dynamic_evidence (
  id               BIGSERIAL PRIMARY KEY,
  scan_id          BIGINT NOT NULL,
  vulnerability_id BIGINT,
  check_kind       TEXT NOT NULL,               -- exported_activity | deep_link | content_provider
  target           TEXT NOT NULL,               -- the component / uri exercised
  outcome          TEXT NOT NULL,               -- confirmed | guarded | refuted | error
  detail           TEXT,
  artifacts        JSONB NOT NULL DEFAULT '{}',
  device_serial    TEXT,
  inserted_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS dynamic_evidence_scan_idx ON workflows.dynamic_evidence (scan_id);
CREATE INDEX IF NOT EXISTS dynamic_evidence_vuln_idx ON workflows.dynamic_evidence (vulnerability_id);
