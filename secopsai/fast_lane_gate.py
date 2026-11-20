"""Replay for the Fast Lane behaviour-floor test.

The plan is ``eval/fast_lane_gate/PLAN.md``, frozen on 2026-11-20 (SHA-256
f460789d08a472bec7ce53049d1d4d78dc080e66924d6f69526bcb676e88235f). Every
constant below comes from it; changing one needs a new held-out window.

Pure functions: ledger digest entries (already labelled by
``secopsai.alert_digest.triage``) and recall-benchmark rows go in; each
variant's severities and the plan's gates come out. Nothing here touches the
Fast Lane or a production setting.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from secopsai.package_features import BEHAVIOUR_RULES
from secopsai.yara_engine import ALERT, WARNING

ORDER = ("none", "low", "medium", "high", "critical")
VARIANTS = ("V0", "V1", "V2", "V3")
# Same set as CRITICAL_BEHAVIOUR in scripts/fast_lane.py (a test keeps them equal).
CRITICAL_BEHAVIOUR = frozenset({"BEH_PTH_STARTUP_INLINE", "BEH_PTH_STARTUP_HARVEST", "BEH_DIFF_NEW_PTH_STARTUP"})
PRESET_KEEP = frozenset({"BEH_PTH_STARTUP_INLINE", "BEH_PTH_STARTUP_HARVEST", "BEH_DIFF_NEW_PTH_STARTUP",
                         "BEH_VERSION_CONFUSION", "BEH_DEPENDENCY_CONFUSION", "BEH_DEPENDENCY_CONFUSION_NPM"})
SCORES = {name: score for name, _ecosystems, _conditions, score in BEHAVIOUR_RULES}

LIVE_SINCE = datetime(2026, 11, 18, 5, 17, tzinfo=timezone.utc)  # #307 on main
SELECTION = (LIVE_SINCE, datetime(2026, 11, 25, tzinfo=timezone.utc))
HELD_OUT = (datetime(2026, 11, 25, tzinfo=timezone.utc), datetime(2026, 12, 2, tzinfo=timezone.utc))
MAX_EXTENSIONS = 2
EXTENSION = timedelta(days=7)
LABEL_DELAY = timedelta(days=7)
HISTORY = timedelta(days=30)
BENCHMARK_SEED = 20261010
BENCHMARK_HELD_OUT = "2026-01-01"

KEEP_MIN_RATE = 0.005
KEEP_MIN_SOLE_SAMPLES = 5
KEEP_MIN_PACKAGES = 20
A1_MIN_CUT = 0.50
A2_MIN_KEPT = 0.95
A3_MIN_CONFIRMED = 10
B1_MAX_DROP_POINTS = 1.0

CONFIRMED = {"known_malicious", "removed"}


def rank(severity: Any) -> int:
    return ORDER.index(severity) if severity in ORDER else 0


def at_least(severity: Any, floor: str) -> bool:
    return rank(severity) >= rank(floor)


def lower(a: str, b: str) -> str:
    return a if rank(a) <= rank(b) else b


def rule_floor(rule: str) -> str:
    """The floor #307 gives one rule: start-up hooks critical, score 70+ high, 60+ medium."""
    if rule in CRITICAL_BEHAVIOUR:
        return "critical"
    score = SCORES.get(rule, 0)
    return "high" if score >= 70 else "medium" if score >= 60 else "none"


def floor_of(rules: Iterable[str], keep: Optional[Iterable[str]] = None) -> str:
    """Severity from behaviour rules alone. With ``keep`` (V2), a rule off the keep-list gives at most low."""
    kept = None if keep is None else set(keep)
    best = "none"
    for rule in rules:
        floor = rule_floor(rule)
        if kept is not None and rule not in kept and floor != "none":
            floor = "low"
        if rank(floor) > rank(best):
            best = floor
    return best


def parse_reason(reason: Any) -> Tuple[Set[str], bool]:
    """(behaviour rule ids, whether any other reason is present) from a Fast Lane digest reason."""
    rules: Set[str] = set()
    other = False
    for part in (p.strip() for p in str(reason or "").split(";")):
        if not part:
            continue
        if part.startswith("behaviour rules:"):
            rules |= {r.strip() for r in part.split(":", 1)[1].split(",") if r.strip()}
        else:
            other = True
    return rules, other


def _when(value: Any) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def alerts(entries: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Fast Lane package alerts, one per alert id (the latest write wins), oldest first."""
    latest: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        when = _when(entry.get("occurred_at"))
        if entry.get("source") != "fast_lane" or when is None or not entry.get("package") or not entry.get("version"):
            continue
        rules, other = parse_reason(entry.get("reason"))
        latest[str(entry.get("alert_id"))] = {
            "alert_id": str(entry.get("alert_id")), "key": (str(entry.get("ecosystem")), str(entry["package"])),
            "version": str(entry["version"]), "when": when, "severity": str(entry.get("severity") or "none"),
            "rules": rules, "behaviour_only": bool(rules) and not other, "group": entry.get("group"),
        }
    return sorted(latest.values(), key=lambda a: (a["when"], a["alert_id"]))


def new_rules(history: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    """V1: the rule ids each alert counts. An id is dropped when the package's most
    recent earlier release with a behaviour rule scoring 60+ (within 30 days) had it."""
    last: Dict[Tuple[str, str], Dict[str, Any]] = {}
    counted: Dict[str, Set[str]] = {}
    for alert in sorted(history, key=lambda a: (a["when"], a["alert_id"])):
        prev = last.get(alert["key"])
        if prev and prev["version"] != alert["version"] and alert["when"] - prev["when"] <= HISTORY:
            counted[alert["alert_id"]] = set(alert["rules"]) - set(prev["rules"])
        else:
            counted[alert["alert_id"]] = set(alert["rules"])
        if any(rule_floor(rule) != "none" for rule in alert["rules"]):
            last[alert["key"]] = alert
    return counted


def severity(alert: Dict[str, Any], variant: str, counted: Dict[str, Set[str]], keep: Iterable[str]) -> str:
    """The alert's severity under a variant. Mixed alerts are unchanged (the plan's
    conservative rule), and a variant never raises an alert above V0."""
    if variant == "V0" or not alert["behaviour_only"]:
        return alert["severity"]
    rules = counted.get(alert["alert_id"], alert["rules"]) if variant in {"V1", "V3"} else alert["rules"]
    floor = floor_of(rules, keep if variant in {"V2", "V3"} else None)
    return lower(alert["severity"], floor)


def keep_list(selection: List[Dict[str, Any]], benchmark: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The plan's mechanical V2 keep-list from the selection window and pre-2026 benchmark samples."""
    raised: Dict[str, Set[Tuple[str, str]]] = {}
    confirmed: Dict[str, Set[Tuple[str, str]]] = {}
    for alert in selection:
        # "Raised" means the floor raised it: behaviour-only alerts (the only ones V2 changes).
        if not alert["behaviour_only"] or not at_least(alert["severity"], "medium"):
            continue
        for rule in alert["rules"]:
            if rule_floor(rule) == "none":
                continue
            raised.setdefault(rule, set()).add(alert["key"])
            if alert.get("group") in CONFIRMED:
                confirmed.setdefault(rule, set()).add(alert["key"])
    sole: Dict[str, int] = {}
    for row in bench_rows(benchmark):
        if row["malicious"] and row["discovered"] < BENCHMARK_HELD_OUT and len(row["behaviour"]) == 1 and row["yara_score"] < WARNING:
            rule = next(iter(row["behaviour"]))
            sole[rule] = sole.get(rule, 0) + 1
    rules = []
    for rule in sorted(name for name in SCORES if rule_floor(name) != "none"):
        n_raised, n_confirmed, n_sole = len(raised.get(rule, ())), len(confirmed.get(rule, ())), sole.get(rule, 0)
        reasons = [label for label, ok in (
            ("preset", rule in PRESET_KEEP),
            ("confirmed_rate", n_confirmed >= 1 and n_confirmed >= KEEP_MIN_RATE * n_raised),
            ("benchmark_sole", n_sole >= KEEP_MIN_SOLE_SAMPLES),
            ("too_few_packages", n_raised < KEEP_MIN_PACKAGES),
        ) if ok]
        rules.append({"rule": rule, "floor": rule_floor(rule), "raised_packages": n_raised, "confirmed_packages": n_confirmed,
                      "benchmark_sole_samples": n_sole, "keep": bool(reasons), "reasons": reasons})
    return {"keep": [r["rule"] for r in rules if r["keep"]], "lowered": [r["rule"] for r in rules if not r["keep"]], "rules": rules}


def bench_rows(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Scanned benchmark rows with their behaviour ids and the YARA part of the score.

    The funnel's score is the YARA score plus each behaviour rule's score, capped
    at 100, so the YARA part is the remainder; at the cap it is a lower bound
    (conservative: YARA then rescues fewer packages under a variant)."""
    out = []
    for row in rows:
        if row.get("status") != "scanned":
            continue
        files = row.get("rule_files") or {}
        behaviour = {key.split(":", 1)[1] for key in files if key.startswith("BEHAVIOUR:")}
        has_yara = any(key.startswith("YARA:") for key in files)
        score = int(row.get("score") or 0)
        rest = score - sum(SCORES.get(rule, 0) for rule in behaviour)
        yara_score = (score if not behaviour else max(0, rest)) if has_yara else 0
        out.append({"key": (str(row.get("ecosystem")), str(row.get("package"))), "version": str(row.get("version")),
                    "discovered": str(row.get("discovered") or ""), "behaviour": behaviour, "yara_score": yara_score,
                    "malicious": row.get("set") == "malicious", "popular": row.get("category") == "popular"})
    return out


def _bench_raised(rows: List[Dict[str, Any]], variant: str, keep: Iterable[str]) -> Dict[int, bool]:
    """Whether each row reaches medium+: the behaviour floor, or a YARA alert (a lone
    YARA warning is low in the Fast Lane since #308). V1 compares each sample with
    the package's previous sample that had a 60+ rule."""
    counted: Dict[int, Set[str]] = {}
    if variant in {"V1", "V3"}:
        last: Dict[Tuple[str, str], Set[str]] = {}
        for index in sorted(range(len(rows)), key=lambda i: (rows[i]["discovered"], rows[i]["version"])):
            row = rows[index]
            prev = last.get(row["key"])
            counted[index] = set(row["behaviour"]) - prev if prev is not None else set(row["behaviour"])
            if any(rule_floor(rule) != "none" for rule in row["behaviour"]):
                last[row["key"]] = set(row["behaviour"])
    out = {}
    for index, row in enumerate(rows):
        rules = counted.get(index, row["behaviour"])
        floor = floor_of(rules, keep if variant in {"V2", "V3"} else None)
        out[index] = at_least(floor, "medium") or row["yara_score"] >= ALERT
    return out


def benchmark_report(rows: Iterable[Dict[str, Any]], keep: Iterable[str]) -> Dict[str, Any]:
    """B1 (held-out malware recall per package, npm and PyPI) and B2 (popular false positives)."""
    scanned = bench_rows(rows)
    held = [r for r in scanned if r["malicious"] and r["discovered"] >= BENCHMARK_HELD_OUT]
    popular = [r for r in scanned if r["popular"]]
    report: Dict[str, Any] = {}
    for variant in VARIANTS:
        raised = _bench_raised(held, variant, keep)
        recall = {}
        for eco in ("npm", "pypi"):
            packages = {r["key"] for r in held if r["key"][0] == eco}
            hit = {held[i]["key"] for i, ok in raised.items() if ok and held[i]["key"][0] == eco}
            recall[eco] = {"packages": len(packages), "raised": len(hit), "recall": round(len(hit) / len(packages), 4) if packages else None}
        fp = sum(_bench_raised(popular, variant, keep).values())
        report[variant] = {"recall": recall, "popular_raised": fp, "popular_rows": len(popular)}
    for variant in VARIANTS[1:]:
        drops = {}
        for eco in ("npm", "pypi"):
            base, now = report["V0"]["recall"][eco]["recall"], report[variant]["recall"][eco]["recall"]
            drops[eco] = None if base is None else round((base - now) * 100, 2)
        report[variant]["b1_drop_points"] = drops
        report[variant]["b1"] = all(d is not None and d <= B1_MAX_DROP_POINTS for d in drops.values())
        report[variant]["b2"] = report[variant]["popular_raised"] <= report["V0"]["popular_raised"]
    return report


def live_report(window: List[Dict[str, Any]], history: List[Dict[str, Any]], keep: Iterable[str], days: float) -> Dict[str, Any]:
    """A1-A3 over the window's alerts (``days`` long). ``history`` holds the window
    and up to 30 days before it, for V1."""
    counted = new_rules(history)
    keep = list(keep)
    days = max(days, 1e-9)
    behaviour = [a for a in window if a["behaviour_only"]]
    recomputed = sum(1 for a in behaviour if floor_of(a["rules"]) != a["severity"])
    base = {a["key"] for a in behaviour if a.get("group") in CONFIRMED and at_least(a["severity"], "medium")}
    ossf = {a["key"] for a in window if a["key"] in base and a.get("group") == "known_malicious"}
    report: Dict[str, Any] = {"alerts": len(window), "behaviour_only": len(behaviour), "v0_floor_mismatch": recomputed,
                              "confirmed_packages": len(base), "ossf_packages": len(ossf),
                              "a3": len(base) >= A3_MIN_CONFIRMED, "variants": {}}
    v0_count = None
    for variant in VARIANTS:
        sev = {a["alert_id"]: severity(a, variant, counted, keep) for a in window}
        reviewable = sum(1 for a in behaviour if at_least(sev[a["alert_id"]], "medium"))
        kept = {a["key"] for a in window if a["key"] in base and a.get("group") in CONFIRMED and at_least(sev[a["alert_id"]], "medium")}
        v0_count = reviewable if variant == "V0" else v0_count
        row = {"behaviour_only_medium_plus": reviewable,
               "delivered_per_day": round(sum(1 for s in sev.values() if s != "none") / days, 1),
               "low": sum(1 for s in sev.values() if s == "low"),
               "confirmed_kept": len(kept), "confirmed_lost": sorted("/".join(k) for k in base - kept),
               "ossf_lost": sorted("/".join(k) for k in ossf - kept)}
        if variant != "V0":
            row["a1_cut"] = round(1 - reviewable / v0_count, 4) if v0_count else 0.0
            row["a1"] = bool(v0_count) and row["a1_cut"] >= A1_MIN_CUT
            row["a2_kept_rate"] = round(len(kept) / len(base), 4) if base else None
            row["a2"] = bool(base) and len(kept) >= A2_MIN_KEPT * len(base) and not (ossf - kept)
        report["variants"][variant] = row
    return report


def rule_table(window: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per rule, over behaviour-only alerts: alerts, packages, confirmed packages."""
    table: Dict[str, Dict[str, Any]] = {}
    for alert in window:
        if not alert["behaviour_only"]:
            continue
        for rule in alert["rules"]:
            row = table.setdefault(rule, {"rule": rule, "alerts": 0, "packages": set(), "confirmed": set()})
            row["alerts"] += 1
            row["packages"].add(alert["key"])
            if alert.get("group") in CONFIRMED:
                row["confirmed"].add(alert["key"])
    return sorted(({"rule": r["rule"], "alerts": r["alerts"], "packages": len(r["packages"]), "confirmed_packages": len(r["confirmed"])}
                   for r in table.values()), key=lambda r: -r["alerts"])


def decide(live: Dict[str, Any], bench: Dict[str, Any], extensions: int) -> Dict[str, Any]:
    """The plan's decision: inconclusive without enough evidence, else the passing
    variant with the largest A1 cut (ties to the simplest, V1 first)."""
    if not live["a3"]:
        more = extensions < MAX_EXTENSIONS
        return {"result": "extend" if more else "inconclusive", "passing": [],
                "note": f"{live['confirmed_packages']} confirmed packages, {A3_MIN_CONFIRMED} needed"
                        + (f"; extend the held-out window by 7 days (extension {extensions + 1} of {MAX_EXTENSIONS})" if more else "; nothing changes")}
    passing = [v for v in VARIANTS[1:] if live["variants"][v]["a1"] and live["variants"][v]["a2"] and bench[v]["b1"] and bench[v]["b2"]]
    if not passing:
        return {"result": "no_change", "passing": [], "note": "no variant passed; the held-out window is spent for these variants"}
    best = max(passing, key=lambda v: (live["variants"][v]["a1_cut"], -VARIANTS.index(v)))
    return {"result": "recommend", "variant": best, "passing": passing, "note": "applying it is the owner's decision"}


def windows(mode: str, extensions: int = 0) -> Tuple[datetime, datetime]:
    if mode == "selection":
        return SELECTION
    if mode == "held_out":
        if not 0 <= extensions <= MAX_EXTENSIONS:
            raise ValueError(f"extensions must be 0-{MAX_EXTENSIONS}")
        return HELD_OUT[0], HELD_OUT[1] + extensions * EXTENSION
    raise ValueError("mode must be selection or held_out")


def labels_ready(end: datetime, now: datetime) -> bool:
    """Labels are taken at least 7 days after the window ends (the plan's label dates)."""
    return now >= end + LABEL_DELAY
