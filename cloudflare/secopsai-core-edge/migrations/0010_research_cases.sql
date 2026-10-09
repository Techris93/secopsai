-- Hosted read model for research cases.  The research worker pushes a
-- bounded, redacted projection of each case (no raw artifacts, no local
-- paths, no disclosure bodies); the full ledger stays with the worker.
CREATE TABLE IF NOT EXISTS research_case_projections (
  workspace_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  case_updated_at TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  case_type TEXT NOT NULL,
  title TEXT NOT NULL,
  summary_json TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  synced_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, case_id),
  CHECK (length(summary_json) <= 16384),
  CHECK (length(detail_json) <= 98304)
);

CREATE INDEX IF NOT EXISTS research_case_projections_recent
  ON research_case_projections (workspace_id, case_updated_at DESC);
