# Fast Lane behaviour-floor test plan

Status: **draft, not frozen**. It becomes the pre-registration when merged to `main`. That must happen before 2026-11-25 00:00 UTC, when the held-out window opens. After the merge, nothing in this file changes. Any later change needs a new held-out window.

## Background

#307 (live on `main` from about 05:17 UTC on 2026-11-18) added a floor to `assess()` in `scripts/fast_lane.py`:

- a release whose top behaviour-rule score is 60 or more is at least `medium`;
- one at 70 or more is at least `high`;
- a start-up hook rule makes it `critical`.

This applies even when nothing else about the release is new. A release that would otherwise be `none` is now delivered: it gets a Core alert, a digest entry and a model triage job.

Observed so far (Alert Digest run 44777142382; part of the selection window below):

| | Before #307 | After #307 |
|---|---|---|
| Fast Lane alerts a day | about 345 | about 2,620 |
| Alerts raised by behaviour rules alone | 0 | 8,155 in 3.5 days |
| ...of which ossf-listed or removed from the registry | n/a | 12 alerts, 11 packages |
| Alerts on a package already alerted with the same rules | n/a | 5,266 of 8,155 |

The recall benchmark measures these rules' false positives on 1,500 popular packages. The live stream is mostly small, new packages, so the benchmark did not predict this volume.

## Variants

All variants change only the behaviour floor. The existing paths stay as they are: install-script change, new execution or egress indicators, YARA, and publisher change.

- **V0, control:** the floor as on `main` today.
- **V1, new behaviour only:** the floor counts only the behaviour rule ids that were not on the package's most recent earlier release with any behaviour rule scoring 60 or more, looked back over 30 days. A package with no such release counts every id. If no id counts, the release keeps the severity of the other paths, and stays undelivered if that is `none`.
- **V2, per-rule floors:** a rule on the keep-list keeps its floor. Every other rule's floor becomes `low`: still delivered, triaged and shown, but no longer `medium` or above. The keep-list is chosen by the rule below, from selection data only.
- **V3:** V1, then V2.

### V2 keep-list rule (applied mechanically, no discretion)

A rule keeps its floor if any of these holds:

1. It is one of: `BEH_PTH_STARTUP_INLINE`, `BEH_PTH_STARTUP_HARVEST`, `BEH_DIFF_NEW_PTH_STARTUP`, `BEH_VERSION_CONFUSION`, `BEH_DEPENDENCY_CONFUSION`, `BEH_DEPENDENCY_CONFUSION_NPM`.
2. In the selection window, it raised at least 1 confirmed package, and its confirmed packages are at least 0.5% of the packages it raised.
3. In the recall benchmark (seed 20261010), on samples discovered **before 2026-01-01**, it is the only rule and there is no YARA warning or alert on at least 5 malware samples.
4. In the selection window, it raised fewer than 20 packages. That is too little data to lower it.

The keep-list is written to `eval/fast_lane_gate/v2-keep-list.json` and committed to `main` by 2026-12-02 23:59 UTC. That is before any held-out label is read.

## Data

- **Source:** the ledger's digest entries (`GET /digest/{day}`), the record of every alert Fast Lane delivered. Under V0, every release with a behaviour rule at 60 or more is delivered, so the replay sees each release any variant could raise. Replays run on GitHub runners with `LEDGER_STORE_TOKEN`. They make no model calls, send no email and download no packages.
- **Selection window:** alerts from 2026-11-18 05:17 to 2026-11-25 00:00 UTC.
- **Held-out window:** alerts from 2026-11-25 00:00 to 2026-12-02 00:00 UTC.
- **Labels:** an alerted version is **confirmed** if, on the label date, ossf/malicious-packages lists that exact version (the install-firewall shards), or the registry no longer serves it (HTTP 404). Everything else is unconfirmed. Both kinds of confirmation are reported separately. The selection window is labelled on 2026-12-02 and the held-out window on 2026-12-09, at least 7 days after each window ends.
- **Mixed alerts:** an alert that also has a non-behaviour reason (install script, YARA, publisher, new indicators) is counted as unchanged under every variant. The digest does not record the other paths' own severity, so this understates every variant's reduction.

## Pass criteria (held-out window, evaluated once)

A variant passes only if all of these hold:

- **A1, volume:** alerts at `medium` or above raised by behaviour rules alone fall by at least 50% against V0.
- **A2, confirmed malware kept:** of the confirmed packages that V0 raises to `medium` or above from behaviour rules alone, the variant still raises at least 95% to `medium` or above. It loses none that ossf lists.
- **A3, enough evidence:** V0 raises at least 10 confirmed packages from behaviour rules alone in the held-out window. If it doesn't, the window is extended by 7 days, at most twice, with labels taken 7 days after the new end. If it is still short, the result is **inconclusive** and nothing changes.
- **B1, benchmark recall:** in the recall benchmark (seed 20261010, run on GitHub runners at the test commit), for samples discovered **on or after 2026-01-01**, the share of malware packages raised to `medium` or above by behaviour rules or YARA falls by at most 1.0 percentage point against V0, for npm and for PyPI separately. Recall is counted per package, so V1's suppression of a later version of an already-raised package is not a loss.
- **B2, benchmark false positives:** popular-package false positives at `medium` or above do not rise. This is a sanity check, since the variants only lower severity.

## Decision

- **One or more variants pass:** recommend the passing variant with the largest A1 reduction. On a tie, recommend V1, as the simplest. Applying it is the user's decision.
- **None pass:** nothing changes. These variants have then used up the held-out window, and a different change needs a new window.
- **No adjustment afterwards:** no threshold, window or label is changed after the held-out labels are read.

## Reported, not gating

- **Triage jobs per day.** V1 removes deliveries, so it removes their triage jobs. V2's `low` alerts are still triaged. Skipping triage for them would be a separate change and a separate test.
- **Other reports:**
  - urgent emails per day;
  - the per-rule table (alerts, packages, confirmed);
  - repeat alerts per package;
  - the confirmed packages each variant loses, by name (all are public through ossf or the registry).

## Known limits

- **Labels are a lower bound.** Undetected malware counts as unconfirmed. A version can also be removed for benign reasons.
- **V1's blind spot.** A hijacked release of a package whose earlier releases already hit the same behaviour rules is raised only by the version-diff paths (`BEH_DIFF_*`, install-script change, YARA). The live labels measure this only when it happens in the window. The benchmark has little version history.
- **The benchmark simulates the floor from rule ids and their scores** (`BEHAVIOUR_RULES` in `secopsai/package_features.py`). It has no install-script or publisher history, so B1 measures the floor and YARA paths only.

## Steps

1. Merge this plan before 2026-11-25 00:00 UTC (freeze).
2. Add the replay: `scripts/fast_lane_gate_replay.py`, unit tests on synthetic alerts, and a manual `fast-lane-gate-replay.yml` workflow. It must not change Fast Lane or any production setting.
3. 2026-12-02: label the selection window, apply the keep-list rule, and commit `v2-keep-list.json`.
4. 2026-12-09: label the held-out window, run V0 to V3 and the benchmark gate once, and report.
