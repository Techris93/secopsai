# Bernstein Integration

This integration keeps `secopsai` as the detection, correlation, and findings source of truth, while using [Bernstein](https://github.com/chernistry/bernstein) as the orchestration dashboard and task runner for remediation work.

## Recommended model

Do **not** replace the `secopsai` SOC store or findings pipeline with Bernstein.

Use:

- `secopsai` for:
  - detection
  - correlation
  - IOC/supply-chain findings
  - triage state
  - Slack / operational security alerts

- `Bernstein` for:
  - remediation task execution
  - live terminal/web dashboard
  - parallel coding agents
  - worktree isolation
  - quality gates

## Install Bernstein

Pick one:

```bash
pipx install bernstein
```

or

```bash
uv tool install bernstein
```

Then initialize Bernstein in this repo:

```bash
cd ~/secopsai
bernstein init
```

Copy the example configuration:

```bash
cp bernstein.yaml.example bernstein.yaml
```

The example configuration already enables Bernstein's `agency` catalog so it can route work to specialist agents when that catalog is available in your Bernstein installation.

## Export SecOpsAI findings into a Bernstein plan

Generate a Bernstein-compatible remediation plan from the current SOC store:

```bash
cd ~/secopsai
source .venv/bin/activate
python scripts/secopsai_to_bernstein.py --severity high --limit 10
```

This writes:

- `.sdd/plans/secopsai-remediation.yaml`
- `.sdd/secopsai/findings/*.md`

The markdown files contain finding-specific context and the plan file maps those findings into Bernstein steps.

Wrapper script:

```bash
bash scripts/secopsai_bernstein_sync.sh
```

## Run Bernstein against the exported plan

```bash
cd ~/secopsai
bernstein run .sdd/plans/secopsai-remediation.yaml
```

Watch progress:

```bash
bernstein live
```

Open the browser dashboard:

```bash
bernstein dashboard
```

If you want to confirm the catalog-backed routing behavior, inspect `bernstein.yaml` and ensure it contains:

```yaml
catalogs:
  - name: agency
    type: agency
    enabled: true
```

## Operator workflow

1. Refresh SecOpsAI findings:

```bash
secopsai refresh
secopsai supply-chain once --top 1000 --slack
```

2. Export actionable findings into Bernstein:

```bash
bash scripts/secopsai_bernstein_sync.sh
```

3. Run the generated Bernstein plan:

```bash
bernstein run .sdd/plans/secopsai-remediation.yaml
```

4. Use Bernstein to:
   - investigate findings
   - propose remediations
   - generate code changes/tests/docs
   - work in isolated branches/worktrees

5. Use `secopsai` to finalize security state:

```bash
secopsai show <FINDING_ID>
secopsai triage <FINDING_ID> --status closed --disposition remediated
```

## What this replaces

If your current "dashboard setup" need is:

- work queue
- progress dashboard
- multi-agent remediation
- cost/status tracking

then Bernstein can replace that orchestration/dashboard layer.

## What this does not replace

Bernstein does not replace:

- `secopsai` findings DB
- correlation engine
- threat intel matching
- supply-chain verdict store
- security finding schema

Those stay in `secopsai`.

## Suggested next step

Start with a side-by-side setup:

```bash
secopsai refresh
bash scripts/secopsai_bernstein_sync.sh
bernstein run .sdd/plans/secopsai-remediation.yaml
bernstein live
```

That gives you a real Bernstein remediation dashboard on top of the existing `secopsai` backend without throwing away the SOC pipeline.
