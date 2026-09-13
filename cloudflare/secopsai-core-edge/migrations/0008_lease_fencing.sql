-- Typed ontology identity and lease fencing.
-- ``0003`` originally enforced UNIQUE(namespace, canonical_key), which made
-- a package and repository with the same source key collide. Rebuild the
-- ontology tables while preserving all rows and foreign-key relationships.
PRAGMA foreign_keys=OFF;

ALTER TABLE ontology_aliases RENAME TO ontology_aliases_legacy_0008;
ALTER TABLE ontology_relationships RENAME TO ontology_relationships_legacy_0008;
ALTER TABLE ontology_events RENAME TO ontology_events_legacy_0008;
ALTER TABLE ontology_entity_merges RENAME TO ontology_entity_merges_legacy_0008;
ALTER TABLE ontology_entities RENAME TO ontology_entities_legacy_0008;

CREATE TABLE ontology_entities_new_0008 (
  entity_id TEXT PRIMARY KEY,
  entity_type TEXT NOT NULL,
  namespace TEXT NOT NULL,
  canonical_key TEXT NOT NULL,
  display_name TEXT NOT NULL,
  source TEXT NOT NULL,
  source_id TEXT NOT NULL DEFAULT '',
  workspace_id TEXT NOT NULL DEFAULT 'hosted',
  owner_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  properties_json TEXT NOT NULL DEFAULT '{}',
  confidence INTEGER NOT NULL DEFAULT 100 CHECK (confidence >= 0 AND confidence <= 100),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  freshness_at TEXT NOT NULL,
  valid_from TEXT,
  valid_to TEXT,
  schema_version TEXT NOT NULL DEFAULT 'secopsai.ontology.v1',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (entity_type, namespace, canonical_key)
);
INSERT INTO ontology_entities_new_0008
  SELECT entity_id, entity_type, namespace, canonical_key, display_name, source,
         source_id, workspace_id, owner_id, status, properties_json, confidence,
         first_seen_at, last_seen_at, observed_at, freshness_at, valid_from,
         valid_to, schema_version, created_at, updated_at
    FROM ontology_entities_legacy_0008;
DROP TABLE ontology_entities_legacy_0008;
ALTER TABLE ontology_entities_new_0008 RENAME TO ontology_entities;

CREATE TABLE ontology_aliases_new_0008 (
  alias_id TEXT PRIMARY KEY,
  entity_id TEXT NOT NULL,
  alias_type TEXT NOT NULL,
  alias_value TEXT NOT NULL,
  normalized_value TEXT NOT NULL,
  source TEXT NOT NULL,
  confidence INTEGER NOT NULL DEFAULT 100 CHECK (confidence >= 0 AND confidence <= 100),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (alias_type, normalized_value, source),
  FOREIGN KEY (entity_id) REFERENCES ontology_entities(entity_id) ON DELETE CASCADE
);
INSERT INTO ontology_aliases_new_0008 SELECT * FROM ontology_aliases_legacy_0008;
DROP TABLE ontology_aliases_legacy_0008;
ALTER TABLE ontology_aliases_new_0008 RENAME TO ontology_aliases;

CREATE TABLE ontology_relationships_new_0008 (
  relationship_id TEXT PRIMARY KEY,
  relationship_type TEXT NOT NULL,
  from_entity_id TEXT NOT NULL,
  to_entity_id TEXT NOT NULL,
  source TEXT NOT NULL,
  source_record_id TEXT NOT NULL DEFAULT '',
  workspace_id TEXT NOT NULL DEFAULT 'hosted',
  evidence_ref_id TEXT,
  properties_json TEXT NOT NULL DEFAULT '{}',
  confidence INTEGER NOT NULL DEFAULT 100 CHECK (confidence >= 0 AND confidence <= 100),
  observed_at TEXT NOT NULL,
  valid_from TEXT,
  valid_to TEXT,
  freshness_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (relationship_type, from_entity_id, to_entity_id, source, source_record_id),
  FOREIGN KEY (from_entity_id) REFERENCES ontology_entities(entity_id) ON DELETE CASCADE,
  FOREIGN KEY (to_entity_id) REFERENCES ontology_entities(entity_id) ON DELETE CASCADE
);
INSERT INTO ontology_relationships_new_0008 SELECT * FROM ontology_relationships_legacy_0008;
DROP TABLE ontology_relationships_legacy_0008;
ALTER TABLE ontology_relationships_new_0008 RENAME TO ontology_relationships;

CREATE TABLE ontology_events_new_0008 (
  event_id TEXT PRIMARY KEY,
  entity_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  source TEXT NOT NULL,
  source_record_id TEXT NOT NULL DEFAULT '',
  summary_json TEXT NOT NULL DEFAULT '{}',
  occurred_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (entity_id) REFERENCES ontology_entities(entity_id) ON DELETE CASCADE
);
INSERT INTO ontology_events_new_0008 SELECT * FROM ontology_events_legacy_0008;
DROP TABLE ontology_events_legacy_0008;
ALTER TABLE ontology_events_new_0008 RENAME TO ontology_events;

CREATE TABLE ontology_entity_merges_new_0008 (
  merge_id TEXT PRIMARY KEY,
  loser_entity_id TEXT NOT NULL,
  winner_entity_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  source TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (loser_entity_id) REFERENCES ontology_entities(entity_id) ON DELETE CASCADE,
  FOREIGN KEY (winner_entity_id) REFERENCES ontology_entities(entity_id) ON DELETE CASCADE
);
INSERT INTO ontology_entity_merges_new_0008 SELECT * FROM ontology_entity_merges_legacy_0008;
DROP TABLE ontology_entity_merges_legacy_0008;
ALTER TABLE ontology_entity_merges_new_0008 RENAME TO ontology_entity_merges;

CREATE UNIQUE INDEX idx_ontology_aliases_entity_value
  ON ontology_aliases(entity_id, alias_type, normalized_value);
CREATE INDEX idx_ontology_entities_type_key
  ON ontology_entities(entity_type, canonical_key);
CREATE INDEX idx_ontology_entities_source_id
  ON ontology_entities(source, source_id);
CREATE INDEX idx_ontology_entities_workspace_owner
  ON ontology_entities(workspace_id, owner_id, updated_at DESC);
CREATE INDEX idx_ontology_entities_freshness
  ON ontology_entities(freshness_at, last_seen_at DESC);
CREATE INDEX idx_ontology_relationships_from_type
  ON ontology_relationships(from_entity_id, relationship_type, updated_at DESC);
CREATE INDEX idx_ontology_relationships_to_type
  ON ontology_relationships(to_entity_id, relationship_type, updated_at DESC);
CREATE INDEX idx_ontology_relationships_workspace
  ON ontology_relationships(workspace_id, observed_at DESC);
CREATE INDEX idx_ontology_events_entity_time
  ON ontology_events(entity_id, occurred_at DESC);
CREATE INDEX idx_ontology_merges_winner
  ON ontology_entity_merges(winner_entity_id, created_at DESC);

CREATE TRIGGER trg_ontology_entities_json_bounds_insert
BEFORE INSERT ON ontology_entities
WHEN length(COALESCE(NEW.properties_json, '{}')) > 65536
BEGIN SELECT RAISE(ABORT, 'ontology entity JSON exceeds the bounded limit'); END;
CREATE TRIGGER trg_ontology_entities_json_bounds_update
BEFORE UPDATE OF properties_json ON ontology_entities
WHEN length(COALESCE(NEW.properties_json, '{}')) > 65536
BEGIN SELECT RAISE(ABORT, 'ontology entity JSON exceeds the bounded limit'); END;

-- Recreate the JSON bounds that migration 0004 attached to the tables rebuilt
-- above.  SQLite drops table-owned triggers with the legacy tables, so leaving
-- these out would make the rebuilt relationship, evidence, and timeline
-- tables accept unbounded control-plane payloads after the typed-identity
-- migration.
CREATE TRIGGER IF NOT EXISTS trg_ontology_relationships_json_bounds_insert
BEFORE INSERT ON ontology_relationships
WHEN length(COALESCE(NEW.properties_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'ontology relationship JSON exceeds the bounded limit'); END;
CREATE TRIGGER IF NOT EXISTS trg_ontology_relationships_json_bounds_update
BEFORE UPDATE OF properties_json ON ontology_relationships
WHEN length(COALESCE(NEW.properties_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'ontology relationship JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_ontology_evidence_json_bounds_insert
BEFORE INSERT ON ontology_evidence_refs
WHEN length(COALESCE(NEW.summary_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'ontology evidence JSON exceeds the bounded limit'); END;
CREATE TRIGGER IF NOT EXISTS trg_ontology_evidence_json_bounds_update
BEFORE UPDATE OF summary_json ON ontology_evidence_refs
WHEN length(COALESCE(NEW.summary_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'ontology evidence JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_ontology_events_json_bounds_insert
BEFORE INSERT ON ontology_events
WHEN length(COALESCE(NEW.summary_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'ontology event JSON exceeds the bounded limit'); END;
CREATE TRIGGER IF NOT EXISTS trg_ontology_events_json_bounds_update
BEFORE UPDATE OF summary_json ON ontology_events
WHEN length(COALESCE(NEW.summary_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'ontology event JSON exceeds the bounded limit'); END;

ALTER TABLE intelligence_jobs ADD COLUMN lease_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE intelligence_jobs ADD COLUMN lease_token TEXT NOT NULL DEFAULT '';
ALTER TABLE coordinator_commands ADD COLUMN lease_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE coordinator_commands ADD COLUMN lease_token TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_intelligence_jobs_lease
  ON intelligence_jobs(job_id, status, worker_id, lease_generation);
CREATE INDEX IF NOT EXISTS idx_coordinator_commands_lease
  ON coordinator_commands(command_id, status, worker_id, lease_generation);

PRAGMA foreign_keys=ON;
