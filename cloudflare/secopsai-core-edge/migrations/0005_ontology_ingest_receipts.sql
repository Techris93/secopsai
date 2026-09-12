-- Idempotency receipts for bounded ontology bridge snapshots.  The receipt
-- stores only the response summary; entity properties and evidence remain in
-- the ontology tables/local runner and are never copied into this table.

CREATE TABLE IF NOT EXISTS ontology_ingest_receipts (
  idempotency_key TEXT PRIMARY KEY,
  request_hash TEXT NOT NULL,
  source_instance TEXT NOT NULL DEFAULT '',
  response_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ontology_ingest_receipts_created
  ON ontology_ingest_receipts(created_at DESC, idempotency_key);

CREATE TRIGGER IF NOT EXISTS trg_ontology_ingest_receipts_response_bound
BEFORE INSERT ON ontology_ingest_receipts
WHEN length(NEW.response_json) > 32768
BEGIN
  SELECT RAISE(ABORT, 'ontology ingest receipt exceeds 32 KiB');
END;

CREATE TRIGGER IF NOT EXISTS trg_ontology_ingest_receipts_update_bound
BEFORE UPDATE OF response_json ON ontology_ingest_receipts
WHEN length(NEW.response_json) > 32768
BEGIN
  SELECT RAISE(ABORT, 'ontology ingest receipt exceeds 32 KiB');
END;
