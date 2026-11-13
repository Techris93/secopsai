# Auto-remediation

SecOpsAI watches its own GitHub Actions runs on `main`, fixes recurring
failures with the agency-agents specialist the catalog routes them to,
verifies the fix itself, and ships it. Module: `secopsai/auto_remediation.py`.

## Loop

Every 30 minutes the `ai.secopsai.auto-remediation` LaunchAgent on the
operator's Mac runs `secopsai remediation tick` from its own clone
(`~/secopsai-remediation`, reset to `origin/main` each time):

1. **Detect.** Each failed run on `main` becomes an incident, grouped by a
   fingerprint of workflow, failed step and the normalized error line.
   Pull request CI is ignored.
2. **Triage.** GitHub or runner outages, third-party upstream failures and the
   watchdog reporting a failed worker run are `external`: recorded and mirrored
   to an issue, never fixed in code, closed after 24 quiet hours. A defect is
   worked on only once it has failed twice; a single failure that does not
   recur expires after 7 days.
3. **Fix.** The routed specialist (for CI failures usually
   `engineering/devops-automator`) runs in an isolated git worktree through the
   existing OpenCodex executor, which forbids commits, pushes, network access
   and secrets, and caps the change at 40 files.
4. **Verify.** This module runs the changed tests, CI's blocking flake8
   selection and `py_compile` on the worktree. A fix without a changed test,
   or with any failing check, is discarded.
5. **Ship.** A verified fix is committed, pushed and opened as a pull request
   labelled `auto-remediation`. In `merge` mode it merges itself once every CI
   check passes, but only if it changes code, tests or docs, includes a test,
   stays within 10 files and 400 added lines, and touches no protected path
   (`.github/`, `cloudflare/`, deploy and dependency files, the bridge, Core
   client, delivery, the specialist roster, or this module). Otherwise it waits
   for a person.
6. **Confirm.** A merged fix is resolved, and its issue closed, only after 48
   hours without the failure. A recurrence reopens the incident; two failed
   attempts hand it to a person (`needs_human`).

At most one new fix starts per tick. A fix interrupted for over 2 hours
returns to the queue.

## Modes

`SECOPSAI_AUTO_REMEDIATION`:

| Mode | Behaviour |
| --- | --- |
| `off` | Nothing runs. |
| `observe` | Records incidents locally; writes nothing to GitHub. |
| `pr` | Opens issues and verified PRs; a person merges. |
| `merge` | As `pr`, and low-risk verified fixes merge themselves after CI. |

## Operate

```bash
scripts/install_auto_remediation.sh merge     # install or change mode
python -m secopsai.cli remediation status     # incidents
python -m secopsai.cli remediation tick --mode observe   # dry run
launchctl bootout gui/$(id -u)/ai.secopsai.auto-remediation   # stop
```

Incidents are followed on GitHub under the `auto-remediation` label. Local
state is in `~/.secopsai-remediation/remediation.db`; logs in
`~/Library/Logs/SecOpsAI/auto-remediation.*.log`.
