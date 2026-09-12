-- Keep evidence references tenant-scoped even though raw evidence remains
-- outside D1. Existing rows are assigned to the hosted Core workspace.
ALTER TABLE ontology_evidence_refs ADD COLUMN workspace_id TEXT NOT NULL DEFAULT 'hosted';

CREATE INDEX IF NOT EXISTS idx_ontology_evidence_workspace
  ON ontology_evidence_refs(workspace_id, observed_at DESC);
