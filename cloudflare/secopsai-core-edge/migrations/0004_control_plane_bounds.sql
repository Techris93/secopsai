-- Keep control-plane JSON bounded even when a route is called outside the
-- Worker.  D1 stores summaries and references only; raw evidence and
-- artifacts remain on the runner or R2.
CREATE TRIGGER IF NOT EXISTS trg_intelligence_jobs_json_bounds_insert
BEFORE INSERT ON intelligence_jobs
WHEN length(COALESCE(NEW.input_json, '{}')) > 65536 OR length(COALESCE(NEW.result_json, '{}')) > 131072
BEGIN SELECT RAISE(ABORT, 'intelligence job JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_intelligence_jobs_json_bounds_update
BEFORE UPDATE OF input_json, result_json ON intelligence_jobs
WHEN length(COALESCE(NEW.input_json, '{}')) > 65536 OR length(COALESCE(NEW.result_json, '{}')) > 131072
BEGIN SELECT RAISE(ABORT, 'intelligence job JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_agent_triage_json_bounds_insert
BEFORE INSERT ON agent_triage_runs
WHEN length(COALESCE(NEW.summary_json, '{}')) > 32768 OR length(COALESCE(NEW.recommendation_json, '{}')) > 32768 OR length(COALESCE(NEW.decision_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'agent triage JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_agent_triage_json_bounds_update
BEFORE UPDATE OF summary_json, recommendation_json, decision_json ON agent_triage_runs
WHEN length(COALESCE(NEW.summary_json, '{}')) > 32768 OR length(COALESCE(NEW.recommendation_json, '{}')) > 32768 OR length(COALESCE(NEW.decision_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'agent triage JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_daily_automation_json_bounds_insert
BEFORE INSERT ON daily_automation_runs
WHEN length(COALESCE(NEW.summary_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'daily automation JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_daily_automation_json_bounds_update
BEFORE UPDATE OF summary_json ON daily_automation_runs
WHEN length(COALESCE(NEW.summary_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'daily automation JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_coordinator_commands_json_bounds_insert
BEFORE INSERT ON coordinator_commands
WHEN length(COALESCE(NEW.payload_json, '{}')) > 32768 OR length(COALESCE(NEW.result_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'coordinator command JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_coordinator_commands_json_bounds_update
BEFORE UPDATE OF payload_json, result_json ON coordinator_commands
WHEN length(COALESCE(NEW.payload_json, '{}')) > 32768 OR length(COALESCE(NEW.result_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'coordinator command JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_runner_heartbeats_json_bounds_insert
BEFORE INSERT ON runner_heartbeats
WHEN length(COALESCE(NEW.storage_json, '{}')) > 16384 OR length(COALESCE(NEW.coordinator_json, '{}')) > 16384
BEGIN SELECT RAISE(ABORT, 'runner heartbeat JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_runner_heartbeats_json_bounds_update
BEFORE UPDATE OF storage_json, coordinator_json ON runner_heartbeats
WHEN length(COALESCE(NEW.storage_json, '{}')) > 16384 OR length(COALESCE(NEW.coordinator_json, '{}')) > 16384
BEGIN SELECT RAISE(ABORT, 'runner heartbeat JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_ontology_entities_json_bounds_insert
BEFORE INSERT ON ontology_entities
WHEN length(COALESCE(NEW.properties_json, '{}')) > 65536
BEGIN SELECT RAISE(ABORT, 'ontology entity JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_ontology_entities_json_bounds_update
BEFORE UPDATE OF properties_json ON ontology_entities
WHEN length(COALESCE(NEW.properties_json, '{}')) > 65536
BEGIN SELECT RAISE(ABORT, 'ontology entity JSON exceeds the bounded limit'); END;

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

CREATE TRIGGER IF NOT EXISTS trg_ontology_metadata_json_bounds_insert
BEFORE INSERT ON ontology_metadata
WHEN length(COALESCE(NEW.value_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'ontology metadata JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_ontology_metadata_json_bounds_update
BEFORE UPDATE OF value_json ON ontology_metadata
WHEN length(COALESCE(NEW.value_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'ontology metadata JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_ontology_changes_json_bounds_insert
BEFORE INSERT ON ontology_change_log
WHEN length(COALESCE(NEW.before_json, '{}')) > 32768 OR length(COALESCE(NEW.after_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'ontology change JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_ontology_changes_json_bounds_update
BEFORE UPDATE OF before_json, after_json ON ontology_change_log
WHEN length(COALESCE(NEW.before_json, '{}')) > 32768 OR length(COALESCE(NEW.after_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'ontology change JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_ontology_conflicts_json_bounds_insert
BEFORE INSERT ON ontology_conflicts
WHEN length(COALESCE(NEW.details_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'ontology conflict JSON exceeds the bounded limit'); END;

CREATE TRIGGER IF NOT EXISTS trg_ontology_conflicts_json_bounds_update
BEFORE UPDATE OF details_json ON ontology_conflicts
WHEN length(COALESCE(NEW.details_json, '{}')) > 32768
BEGIN SELECT RAISE(ABORT, 'ontology conflict JSON exceeds the bounded limit'); END;
