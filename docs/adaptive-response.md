# Adaptive Response Layer

SecOpsAI now includes an Adaptive Response Layer that turns stored findings into risk scoring, response guidance, and durable decision memory.

The core loop is:

```text
observe -> detect pattern -> adapt response -> remember outcome
```

## Run It

```bash
secopsai adaptive-response
secopsai --json adaptive-response --persist-memory
```

`--persist-memory` writes decaying threat memory and confidence trails under `data/adaptive_response/` so repeated traits can influence future runs.

## Capabilities

| Capability | SecOpsAI behavior |
|---|---|
| Baseline detection | Detect obvious threats, raise sensitivity during clusters, remember attacker traits, and recommend containment. |
| Confidence memory | Leave decaying confidence trails on recurring incident traits. |
| Signal routing | Connect weak signals across users, hosts, packages, rules, sessions, platforms, and sources. |
| Triage coordination | Coordinate alert triage with simple local heuristics. |
| Adversarial simulation | Generate red-team/blue-team simulation ideas for attacker adaptation. |
| Layered defense | Recommend blast containment, access tightening, logging escalation, and repair notes. |
| Time-aware detection | Raise anomaly sensitivity for off-hours and weekend activity. |
| Priority routing | Allocate analyst attention to the highest-risk shared roots first. |
| Validation probes | Suggest safe, non-destructive probes for suspicious entities. |
| Deception controls | Recommend honeypots, canaries, and deception paths near high-interest traits. |

## Where It Appears

- `secopsai adaptive-response` prints response posture, adaptive finding scores, safe probes, and memory state.
- `secopsai triage summary` embeds an adaptive response snapshot in JSON and Markdown reports.
- `secopsai triage orchestrate` includes the adaptive response snapshot in orchestrator reports.

## Operator Use

1. Refresh findings:

```bash
secopsai refresh
secopsai correlate
```

2. Run adaptive response:

```bash
secopsai adaptive-response --persist-memory
```

3. Use the output:

- Review `response_posture.mode` to decide whether to tighten access and increase logging.
- Review `priority_routing.asset_priorities` to decide which shared entity to investigate first.
- Review `validation_probes.safe_probes` for low-risk validation steps.
- Review `deception_controls.deception_recommendations` for honeypot or canary placement.
