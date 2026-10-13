-- Bounded read projection. Evidence and review decisions stay in the ledger.
CREATE TABLE IF NOT EXISTS research_operation_projections (
  workspace_id TEXT PRIMARY KEY,
  projection_json TEXT NOT NULL CHECK(length(projection_json) <= 131072),
  synced_at TEXT NOT NULL
);
