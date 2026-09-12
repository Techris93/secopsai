-- Canonical security ontology.  This is additive: source-specific records and
-- raw artifacts remain in their owning stores; D1 keeps bounded summaries and
-- relationships for the hosted operating picture.
CREATE TABLE IF NOT EXISTS ontology_entities (
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
  schema_version TEXT NOT NULL DEFAULT 'secopsai.ontology.v1',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (namespace, canonical_key)
);

CREATE TABLE IF NOT EXISTS ontology_aliases (
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

CREATE TABLE IF NOT EXISTS ontology_relationships (
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

CREATE TABLE IF NOT EXISTS ontology_evidence_refs (
  evidence_ref_id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  locator TEXT NOT NULL,
  content_hash TEXT NOT NULL DEFAULT '',
  content_type TEXT NOT NULL DEFAULT '',
  summary_json TEXT NOT NULL DEFAULT '{}',
  observed_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (source, locator, content_hash)
);

CREATE TABLE IF NOT EXISTS ontology_events (
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

CREATE TABLE IF NOT EXISTS ontology_entity_merges (
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

CREATE TABLE IF NOT EXISTS ontology_metadata (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ontology_change_log (
  change_id TEXT PRIMARY KEY,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  action TEXT NOT NULL,
  before_json TEXT NOT NULL DEFAULT '{}',
  after_json TEXT NOT NULL DEFAULT '{}',
  source TEXT NOT NULL DEFAULT 'unknown',
  actor TEXT NOT NULL DEFAULT 'system',
  occurred_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ontology_conflicts (
  conflict_id TEXT PRIMARY KEY,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  conflict_type TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'open',
  source TEXT NOT NULL DEFAULT 'reconciler',
  created_at TEXT NOT NULL,
  resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_ontology_entities_type_key
  ON ontology_entities(entity_type, canonical_key);
CREATE INDEX IF NOT EXISTS idx_ontology_entities_source_id
  ON ontology_entities(source, source_id);
CREATE INDEX IF NOT EXISTS idx_ontology_entities_workspace_owner
  ON ontology_entities(workspace_id, owner_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ontology_entities_freshness
  ON ontology_entities(freshness_at, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_ontology_aliases_entity
  ON ontology_aliases(entity_id, alias_type, normalized_value);
CREATE INDEX IF NOT EXISTS idx_ontology_relationships_from_type
  ON ontology_relationships(from_entity_id, relationship_type, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ontology_relationships_to_type
  ON ontology_relationships(to_entity_id, relationship_type, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ontology_relationships_workspace
  ON ontology_relationships(workspace_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ontology_evidence_source
  ON ontology_evidence_refs(source, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ontology_events_entity_time
  ON ontology_events(entity_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ontology_merges_winner
  ON ontology_entity_merges(winner_entity_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ontology_changes_object_time
  ON ontology_change_log(object_type, object_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ontology_conflicts_status_time
  ON ontology_conflicts(status, created_at DESC);
