-- Add validity windows to entities while preserving existing D1 rows.
-- Wrangler applies numbered migrations once and keeps this change additive.
ALTER TABLE ontology_entities ADD COLUMN valid_from TEXT;
ALTER TABLE ontology_entities ADD COLUMN valid_to TEXT;

CREATE INDEX IF NOT EXISTS idx_ontology_entities_validity
  ON ontology_entities(valid_from, valid_to, freshness_at);
