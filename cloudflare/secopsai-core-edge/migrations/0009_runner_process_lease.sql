-- Fence runner heartbeats and hosted coordinator result materialization by
-- the worker process that owns the runner lease.  These columns are additive
-- so an existing runner row can be adopted by a fresh process with a higher
-- process_generation during a controlled restart.
ALTER TABLE runner_heartbeats ADD COLUMN process_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runner_heartbeats ADD COLUMN process_revision TEXT NOT NULL DEFAULT '';
ALTER TABLE runner_heartbeats ADD COLUMN process_started_at TEXT;
ALTER TABLE runner_heartbeats ADD COLUMN lease_token TEXT NOT NULL DEFAULT '';
ALTER TABLE runner_heartbeats ADD COLUMN lease_until TEXT;

-- Materialized hosted results carry the process proof that produced them, so
-- a late heartbeat from an old process cannot overwrite a current schedule.
ALTER TABLE daily_automation_runs ADD COLUMN owner_worker_id TEXT NOT NULL DEFAULT '';
ALTER TABLE daily_automation_runs ADD COLUMN process_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE daily_automation_runs ADD COLUMN lease_token TEXT NOT NULL DEFAULT '';
ALTER TABLE daily_automation_settings ADD COLUMN updated_by_worker_id TEXT NOT NULL DEFAULT '';
ALTER TABLE daily_automation_settings ADD COLUMN updated_process_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE daily_automation_settings ADD COLUMN updated_lease_token TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_runner_heartbeats_process_lease
  ON runner_heartbeats(worker_id, process_generation, lease_until, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_daily_automation_runs_process_lease
  ON daily_automation_runs(run_id, owner_worker_id, process_generation);
