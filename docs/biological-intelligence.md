# Biological Intelligence Layer

SecOpsAI now includes a Biological Intelligence Layer that turns stored findings into adaptive security guidance.

The core loop is:

```text
observe -> detect pattern -> adapt response -> remember outcome
```

## Run It

```bash
secopsai bio-intel
secopsai --json bio-intel --persist-memory
```

`--persist-memory` writes decaying threat memory and pheromone trails under `data/biological_intelligence/` so repeated traits can influence future runs.

## Nature Models Implemented

| Nature model | SecOpsAI behavior |
|---|---|
| Immune system | Detect obvious threats, raise sensitivity during clusters, remember attacker traits, and recommend containment. |
| Ant colonies | Leave decaying confidence trails on recurring incident traits. |
| Mycelium networks | Connect weak signals across users, hosts, packages, rules, sessions, platforms, and sources. |
| Flocking birds | Coordinate alert triage with simple local heuristics. |
| Predator-prey cycles | Generate red-team/blue-team simulation ideas for attacker adaptation. |
| Skin | Recommend layered defense, blast containment, access tightening, logging escalation, and self-healing notes. |
| Circadian rhythm | Raise anomaly sensitivity for off-hours and weekend activity. |
| Tree roots | Allocate analyst attention to the highest-risk shared roots first. |
| Echolocation | Suggest safe, non-destructive probes for suspicious entities. |
| Octopus camouflage | Recommend honeypots, canaries, and deception paths near high-interest traits. |

## Where It Appears

- `secopsai bio-intel` prints immune mode, adaptive finding scores, safe probes, and memory state.
- `secopsai triage summary` embeds a biological intelligence snapshot in JSON and Markdown reports.
- `secopsai triage orchestrate` includes the biological intelligence snapshot in orchestrator reports.

## Operator Use

1. Refresh findings:

```bash
secopsai refresh
secopsai correlate
```

2. Run biological intelligence:

```bash
secopsai bio-intel --persist-memory
```

3. Use the output:

- Review `immune_system.mode` to decide whether to tighten access and increase logging.
- Review `tree_roots.asset_priorities` to decide which shared entity to investigate first.
- Review `echolocation.safe_probes` for low-risk validation steps.
- Review `octopus_camouflage.deception_recommendations` for honeypot or canary placement.
