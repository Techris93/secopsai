# Operational Queue Recovery

SecOpsAI keeps every investigation and model attempt as an audit record, but
Mission Control presents the latest actionable state. This distinction prevents
old retries from looking like thousands of active investigations while keeping
the evidence needed for incident review.

## What the counters mean

- **Running investigations** is one current run per finding that is actively
  collecting, analysing, or running. **Queued backlog** is current work waiting
  for a worker; it is not counted as running capacity.
- **Awaiting model** is current work waiting for the explicitly selected model.
  It is never silently moved to a different model.
- **Needs recovery** is current evidence-gap or failed work that has a safe
  retry path. A run at its attempt limit remains blocked for an operator.
- **Historical attempts** is the full append-only run count. It is audit and
  capacity context, not new work to start again.

The same rule is used for model jobs and case pipelines in the dashboard: one
current pipeline row is shown, with the child stages and older attempts kept
behind the row or in the case timeline.

## Automatic recovery

The daily workflow includes a bounded `intelligence_queue_recovery` step. The
local bridge also performs this check before claiming a job:

1. Provider-wait jobs are released only when their captured model is healthy.
   Jobs captured for another model stay parked. Legacy rows without a captured
   model are bound to the current selected model before release or claim (and
   use selected-model-only execution unless they already recorded a fallback
   policy).
2. Only failed `bridge_failed` jobs with a transport marker (timeout, 429/426,
   adapter EOF, connection reset, or equivalent) are requeued.
3. Recovery is limited to ten jobs per pass, requires a five-minute age, and
   stops at three attempts. Invalid model output and validation failures remain
   failed for review rather than being hidden by retries.
4. Investigation backfill is capped at twice the configured active-worker
   capacity. Existing queued rows are preserved; a new cycle reports that it
   was deferred when the queue is already over capacity.

The dashboard exposes **Recover transient failures** and
**Recover and run due investigations**. Both call typed, allowlisted helper
actions. They do not change fallback policy, delete rows, or execute packages.

For an explicit read-only recovery pass, use:

```bash
secopsai intelligence jobs recover --limit 10 --max-attempts 3 --min-age-seconds 300 --json
secopsai intelligence autopilot investigations run-due --json
```

Use the case or job detail/audit view for a permanent failure. Requeue it only
after the provider, artifact source, or missing evidence named in the blocker
has been repaired.

## Collector coverage states

Registry coverage is also separated into current and historical information:

- **Healthy** means the latest successful cursor/window is progressing and no
  current dead letters or unresolved gap exist.
- **Coverage gap** means the latest window stopped before its expected end and
  needs replay.
- **Stale** means the cursor has not progressed within the adapter's freshness
  budget, even if its last run returned successfully.
- **Dead letters pending**, **last run failed**, and **retention risk** are
  explicit current states.

Older failed windows remain immutable evidence and are labelled **historical**
after a later successful cursor/window supersedes them. They are not counted as
active gaps and do not make a feed look clean: a current stale cursor or active
gap still requires attention.

Inspect the state from the CLI or Research → Global coverage:

```bash
secopsai research collect status --json
secopsai research collect coverage --days 7 --json
secopsai research worker due --json
```

Run one bounded collector pass only after confirming it is due. Do not start
overlapping workers; the cursor is advanced only after the selected pages are
persisted.

## Safe operator workflow

1. Refresh **Automation → Jobs** and **Automation → Investigations**. Read the
   current row and blocker, not the historical total.
2. Confirm the selected model and fallback policy in **Automation → Models**.
   If fallback is disabled, a provider outage correctly leaves jobs queued.
3. Run **Recover transient failures** once. Wait for the bridge lease and
   refresh; repeated clicks do not improve a provider outage.
4. Repair the named source or provider, then use **Retry** on a bounded failed
   case. Permanent validation errors require evidence or configuration changes.
5. Review **Research → Global coverage**. Replay active gaps and investigate
   stale cursors; historical windows need no destructive cleanup.
6. In **Research → Cases**, use the decision card. Severity is priority only;
   assessment, evidence quality, local exposure, and confidence determine what
   is actually established.

No recovery action approves a verdict, submits a sandbox sample, sends
disclosure, publishes, deploys, or deletes evidence. All such decisions remain
explicit operator gates.
