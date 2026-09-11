-- Hosted control-plane state.  Raw findings, package archives, and model
-- context stay on the Python runner/local ledger; D1 stores bounded metadata.

CREATE TABLE IF NOT EXISTS intelligence_jobs (
  job_id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  target_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'queued',
  requested_by TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  attempt INTEGER NOT NULL DEFAULT 0,
  provider TEXT NOT NULL DEFAULT '',
  worker_id TEXT NOT NULL DEFAULT '',
  queued_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT,
  updated_at TEXT NOT NULL,
  lease_until TEXT,
  error_code TEXT,
  error_message TEXT,
  input_json TEXT NOT NULL DEFAULT '{}',
  result_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_intelligence_jobs_status_queue
  ON intelligence_jobs(status, queued_at, job_id);
CREATE INDEX IF NOT EXISTS idx_intelligence_jobs_updated
  ON intelligence_jobs(updated_at DESC, job_id DESC);

CREATE TABLE IF NOT EXISTS intelligence_job_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  message TEXT NOT NULL,
  data_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  FOREIGN KEY (job_id) REFERENCES intelligence_jobs(job_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_intelligence_job_events_job
  ON intelligence_job_events(job_id, event_id);

CREATE TABLE IF NOT EXISTS agent_triage_settings (
  settings_id INTEGER PRIMARY KEY CHECK (settings_id = 1),
  mode TEXT NOT NULL DEFAULT 'guarded',
  selected_model TEXT NOT NULL DEFAULT 'google-antigravity/gemini-3.7-flash',
  poll_interval_seconds INTEGER NOT NULL DEFAULT 30,
  min_auto_close_confidence INTEGER NOT NULL DEFAULT 97,
  min_evidence_refs INTEGER NOT NULL DEFAULT 2,
  max_records_per_cycle INTEGER NOT NULL DEFAULT 10,
  auto_create_tuning_proposals INTEGER NOT NULL DEFAULT 1,
  auto_activate_tuning INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_triage_runs (
  run_id TEXT PRIMARY KEY,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  status TEXT NOT NULL,
  intelligence_job_id TEXT,
  selected_model TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT '',
  summary_json TEXT NOT NULL DEFAULT '{}',
  recommendation_json TEXT NOT NULL DEFAULT '{}',
  decision_json TEXT NOT NULL DEFAULT '{}',
  final_action TEXT NOT NULL DEFAULT '',
  reversible INTEGER NOT NULL DEFAULT 1,
  queued_at TEXT NOT NULL,
  completed_at TEXT,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_triage_runs_status_updated
  ON agent_triage_runs(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS agent_triage_tuning_proposals (
  proposal_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  target TEXT NOT NULL,
  status TEXT NOT NULL,
  summary_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_triage_tuning_status
  ON agent_triage_tuning_proposals(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS daily_automation_settings (
  settings_id INTEGER PRIMARY KEY CHECK (settings_id = 1),
  enabled INTEGER NOT NULL DEFAULT 1,
  interval_seconds INTEGER NOT NULL DEFAULT 21600,
  max_alert_reviews INTEGER NOT NULL DEFAULT 25,
  max_investigations INTEGER NOT NULL DEFAULT 5,
  max_candidate_cases INTEGER NOT NULL DEFAULT 5,
  auto_promote_candidates INTEGER NOT NULL DEFAULT 1,
  run_learning INTEGER NOT NULL DEFAULT 1,
  last_run_at TEXT,
  next_run_at TEXT,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS daily_automation_runs (
  run_id TEXT PRIMARY KEY,
  trigger TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  next_run_at TEXT,
  summary_json TEXT NOT NULL DEFAULT '{}',
  error_message TEXT,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_daily_automation_runs_status_time
  ON daily_automation_runs(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS daily_automation_steps (
  step_id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  step_name TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  result_json TEXT NOT NULL DEFAULT '{}',
  error_message TEXT,
  FOREIGN KEY (run_id) REFERENCES daily_automation_runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_daily_automation_steps_run
  ON daily_automation_steps(run_id, step_id);

CREATE TABLE IF NOT EXISTS mcp_client_sessions (
  session_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  client_name TEXT NOT NULL,
  subject_id TEXT NOT NULL DEFAULT '',
  organization_id TEXT NOT NULL DEFAULT '',
  workspace_id TEXT NOT NULL DEFAULT 'hosted',
  transport TEXT NOT NULL DEFAULT 'streamable-http',
  scopes_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active',
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  revoked_at TEXT,
  revoked_by TEXT,
  last_tool TEXT NOT NULL DEFAULT '',
  request_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_mcp_sessions_status_activity
  ON mcp_client_sessions(status, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS mcp_client_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  tool_name TEXT NOT NULL DEFAULT '',
  request_id TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  occurred_at TEXT NOT NULL,
  FOREIGN KEY (session_id) REFERENCES mcp_client_sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mcp_events_session_time
  ON mcp_client_events(session_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS coordinator_commands (
  command_id TEXT PRIMARY KEY,
  command_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  requested_by TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  payload_json TEXT NOT NULL DEFAULT '{}',
  result_json TEXT NOT NULL DEFAULT '{}',
  worker_id TEXT NOT NULL DEFAULT '',
  queued_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT,
  updated_at TEXT NOT NULL,
  lease_until TEXT,
  error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_coordinator_commands_status_queue
  ON coordinator_commands(status, queued_at, command_id);
CREATE INDEX IF NOT EXISTS idx_coordinator_commands_updated
  ON coordinator_commands(updated_at DESC, command_id DESC);

CREATE TABLE IF NOT EXISTS runner_heartbeats (
  worker_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_cycle_at TEXT,
  last_cycle_status TEXT NOT NULL DEFAULT '',
  storage_json TEXT NOT NULL DEFAULT '{}',
  coordinator_json TEXT NOT NULL DEFAULT '{}',
  error_message TEXT,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runner_heartbeats_seen
  ON runner_heartbeats(last_seen_at DESC);

INSERT OR IGNORE INTO agent_triage_settings (
  settings_id, mode, selected_model, poll_interval_seconds,
  min_auto_close_confidence, min_evidence_refs, max_records_per_cycle,
  auto_create_tuning_proposals, auto_activate_tuning, updated_at, updated_by
) VALUES (
  1, 'guarded', 'google-antigravity/gemini-3.7-flash', 30,
  97, 2, 10, 1, 1, '1970-01-01T00:00:00Z', 'migration'
);

INSERT OR IGNORE INTO daily_automation_settings (
  settings_id, enabled, interval_seconds, max_alert_reviews,
  max_investigations, max_candidate_cases, auto_promote_candidates,
  run_learning, updated_at, updated_by
) VALUES (1, 1, 21600, 25, 5, 5, 1, 1, '1970-01-01T00:00:00Z', 'migration');
