"""
SecOps Autoresearch — Detection Explainability
Generates human-readable reason codes and matched-feature summaries for
every detection so analysts understand WHY an alert fired.

Usage:
    from explain import explain_all, write_explanations, format_markdown

DO NOT MODIFY THIS FILE. The agent only modifies detect.py.
"""

import json
import math
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
EXPLANATIONS_FILE = os.path.join(DATA_DIR, "explanations.json")
MITRE_BASE_URL = "https://attack.mitre.org/techniques/"


# ═══ Helpers ════════════════════════════════════════════════════════════════

def _mitre_url(technique_id: str) -> str:
    tid = technique_id.replace(".", "/")
    return f"{MITRE_BASE_URL}{tid}/"


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _parse_ts(ts: str) -> datetime:
    normalized = ts[:-1] if ts.endswith("Z") else ts
    return datetime.fromisoformat(normalized)


def _minutes_between(a: Dict, b: Dict) -> float:
    return (_parse_ts(b["timestamp"]) - _parse_ts(a["timestamp"])).total_seconds() / 60.0


def _base_domain(query: str) -> str:
    parts = query.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else query.lower()


def _first_label(query: str) -> str:
    return query.lower().split(".", 1)[0]


def _average(vals: List[float]) -> float:
    return sum(vals) / len(vals) if vals else 0.0


def _cv(vals: List[float]) -> float:
    """Coefficient of variation."""
    if len(vals) < 2:
        return 0.0
    avg = _average(vals)
    if avg == 0:
        return 0.0
    variance = sum((v - avg) ** 2 for v in vals) / len(vals)
    return math.sqrt(variance) / avg


def _make_explanation(
    event_id: str,
    rule_id: str,
    rule_name: str,
    mitre: str,
    reason: str,
    features: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "event_id":  event_id,
        "rule_id":   rule_id,
        "rule_name": rule_name,
        "mitre":     mitre,
        "mitre_url": _mitre_url(mitre),
        "reason":    reason,
        "features":  features,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }


# ═══ Per-Rule Explainers ════════════════════════════════════════════════════

def explain_brute_force(events: List[Dict], detected_ids: Set[str]) -> List[Dict]:
    """Explain each brute-force cluster with failure count, window, and compromise flag."""
    from detect import RULE_THRESHOLDS, is_external_ip  # type: ignore

    t = RULE_THRESHOLDS["brute_force"]
    RAPID_WINDOW = t["RAPID_WINDOW_MINUTES"]
    COMPROMISE_WINDOW = t["COMPROMISE_WINDOW_MINUTES"]

    failures_by_actor: Dict[Tuple, List[Dict]] = defaultdict(list)
    successes_by_actor: Dict[Tuple, List[Dict]] = defaultdict(list)

    for ev in events:
        if ev.get("sourcetype") != "auth":
            continue
        actor = (ev.get("src_ip", ""), ev.get("user", ""))
        if ev.get("action") == "failure":
            failures_by_actor[actor].append(ev)
        elif ev.get("action") == "success":
            successes_by_actor[actor].append(ev)

    explanations = []
    for actor, failures in failures_by_actor.items():
        src_ip, user = actor
        detected_in_cluster = [f for f in failures if f["event_id"] in detected_ids]
        if not detected_in_cluster:
            continue

        ordered = sorted(failures, key=lambda e: e["timestamp"])
        ordered_successes = sorted(successes_by_actor.get(actor, []), key=lambda e: e["timestamp"])

        window_minutes = (
            _minutes_between(ordered[0], ordered[-1]) if len(ordered) > 1 else 0.0
        )

        last_failure = ordered[-1]
        compromise = any(
            0 <= _minutes_between(last_failure, s) <= COMPROMISE_WINDOW
            for s in ordered_successes
        )

        reason = (
            f"{len(ordered)} failed login{'s' if len(ordered) > 1 else ''} "
            f"in {window_minutes:.1f} min"
            f"{f' from {src_ip}' if src_ip else ''}"
            f"{f' targeting user {user}' if user else ''}"
            f"{' — credential compromise detected' if compromise else ''}"
        )

        features = {
            "failure_count":        len(ordered),
            "window_minutes":       round(window_minutes, 2),
            "src_ip":               src_ip or None,
            "target_user":          user or None,
            "is_external_ip":       is_external_ip(src_ip),
            "subsequent_success":   compromise,
            "rapid_window_used":    RAPID_WINDOW,
        }

        for ev in detected_in_cluster:
            explanations.append(_make_explanation(
                ev["event_id"], "RULE-001", "Brute Force", "T1110", reason, features
            ))

    return explanations


def explain_dns_exfiltration(events: List[Dict], detected_ids: Set[str]) -> List[Dict]:
    """Explain each DNS exfil cluster with entropy, query count, and subdomain stats."""
    queries_by_group: Dict[Tuple, List[Dict]] = defaultdict(list)

    for ev in events:
        if ev.get("sourcetype") == "dns":
            query = ev.get("query", "")
            groups_key = (ev.get("src_ip", ""), _base_domain(query))
            queries_by_group[groups_key].append(ev)

    explanations = []
    for (src_ip, domain), queries in queries_by_group.items():
        detected_in_cluster = [q for q in queries if q["event_id"] in detected_ids]
        if not detected_in_cluster:
            continue

        labels = [_first_label(q.get("query", "")) for q in queries]
        avg_len = _average([len(lbl) for lbl in labels])
        max_entropy = max((_shannon_entropy(lbl) for lbl in labels), default=0.0)
        unique_ratio = len(set(labels)) / len(labels) if labels else 0.0
        has_txt = any(q.get("query_type") == "TXT" for q in queries)

        reason = (
            f"{len(queries)} DNS queries to {domain} from {src_ip} "
            f"with avg label length {avg_len:.0f}, "
            f"entropy {max_entropy:.2f}, "
            f"unique ratio {unique_ratio:.0%}"
            f"{' (TXT records observed)' if has_txt else ''}"
        )

        features = {
            "src_ip":              src_ip,
            "base_domain":         domain,
            "query_count":         len(queries),
            "avg_label_length":    round(avg_len, 2),
            "max_entropy":         round(max_entropy, 4),
            "unique_label_ratio":  round(unique_ratio, 4),
            "has_txt_queries":     has_txt,
        }

        for ev in detected_in_cluster:
            explanations.append(_make_explanation(
                ev["event_id"], "RULE-002", "DNS Exfiltration", "T1048.003", reason, features
            ))

    return explanations


def explain_c2_beaconing(events: List[Dict], detected_ids: Set[str]) -> List[Dict]:
    """Explain each C2 beaconing cluster with periodicity, payload size, and port."""
    connections: Dict[str, List[Dict]] = defaultdict(list)

    for ev in events:
        if (ev.get("sourcetype") == "firewall"
                and ev.get("direction") == "outbound"
                and ev.get("action") == "allowed"):
            key = f"{ev.get('src_ip')}:{ev.get('dest_ip')}"
            connections[key].append(ev)

    explanations = []
    for key, conn_events in connections.items():
        detected_in_cluster = [c for c in conn_events if c["event_id"] in detected_ids]
        if not detected_in_cluster:
            continue

        ordered = sorted(conn_events, key=lambda e: e["timestamp"])
        deltas = [
            (_parse_ts(b["timestamp"]) - _parse_ts(a["timestamp"])).total_seconds()
            for a, b in zip(ordered, ordered[1:])
        ]
        avg_interval = _average(deltas)
        interval_cv  = _cv(deltas)
        ports = sorted(
            {
                dest_port
                for ev in ordered
                for dest_port in [ev.get("dest_port")]
                if isinstance(dest_port, int)
            }
        )
        max_bytes_out = max((ev.get("bytes_out", 0) for ev in ordered), default=0)
        max_bytes_in  = max((ev.get("bytes_in", 0) for ev in ordered), default=0)

        src_ip, dest_ip = key.split(":", 1)

        reason = (
            f"{len(ordered)} connections from {src_ip} → {dest_ip} "
            f"avg interval {avg_interval:.0f}s (CV={interval_cv:.2f}) "
            f"max {max_bytes_out}B out / {max_bytes_in}B in"
            f"{f' on port(s) {ports}' if ports else ''}"
        )

        features = {
            "src_ip":         src_ip,
            "dest_ip":        dest_ip,
            "connection_count": len(ordered),
            "avg_interval_s": round(avg_interval, 2),
            "interval_cv":    round(interval_cv, 4),
            "dest_ports":     ports,
            "max_bytes_out":  max_bytes_out,
            "max_bytes_in":   max_bytes_in,
        }

        for ev in detected_in_cluster:
            explanations.append(_make_explanation(
                ev["event_id"], "RULE-003", "C2 Beaconing", "T1071", reason, features
            ))

    return explanations


def explain_lateral_movement(events: List[Dict], detected_ids: Set[str]) -> List[Dict]:
    """Explain each lateral movement cluster with dest breadth, timing, and transfer size."""
    from detect import is_internal_ip  # type: ignore

    smb_by_src: Dict[str, List[Dict]] = defaultdict(list)
    for ev in events:
        if ev.get("sourcetype") == "firewall" and ev.get("dest_port") == 445:
            smb_by_src[ev.get("src_ip", "")].append(ev)

    explanations = []
    for src_ip, smb_events in smb_by_src.items():
        detected_in_cluster = [e for e in smb_events if e["event_id"] in detected_ids]
        if not detected_in_cluster:
            continue

        ordered = sorted(smb_events, key=lambda e: e["timestamp"])
        unique_dests = sorted(
            {
                dest_ip
                for e in ordered
                for dest_ip in [e.get("dest_ip")]
                if isinstance(dest_ip, str)
            }
        )
        window_minutes = (
            _minutes_between(ordered[0], ordered[-1]) if len(ordered) > 1 else 0.0
        )
        deltas = [
            (_parse_ts(b["timestamp"]) - _parse_ts(a["timestamp"])).total_seconds()
            for a, b in zip(ordered, ordered[1:])
        ]
        avg_gap = _average(deltas)
        max_bytes = max((e.get("bytes_out", 0) for e in ordered), default=0)

        reason = (
            f"SMB connections from {src_ip} to {len(unique_dests)} "
            f"internal host{'s' if len(unique_dests) > 1 else ''} "
            f"in {window_minutes:.1f} min (avg gap {avg_gap:.0f}s, "
            f"max {max_bytes:,}B transferred)"
        )

        features = {
            "src_ip":          src_ip,
            "unique_dests":    len(unique_dests),
            "dest_ips":        unique_dests[:10],   # cap to avoid large payloads
            "window_minutes":  round(window_minutes, 2),
            "avg_gap_seconds": round(avg_gap, 2),
            "max_bytes_out":   max_bytes,
            "is_internal_src": is_internal_ip(src_ip),
        }

        for ev in detected_in_cluster:
            explanations.append(_make_explanation(
                ev["event_id"], "RULE-004", "Lateral Movement (SMB)", "T1021.002", reason, features
            ))

    return explanations


def explain_powershell_abuse(events: List[Dict], detected_ids: Set[str]) -> List[Dict]:
    """Explain PowerShell abuse detections with matched pattern and command excerpt."""
    import re

    PATTERNS = [
        (r"(?i)(encodedcommand|-enc\b)",             "encoded command"),
        (r"(?i)(bypass)",                             "ExecutionPolicy Bypass"),
        (r"(?i)(hidden)",                             "hidden window"),
        (r"(?i)(invoke-mimikatz|invoke-expression|iex\b)", "code injection (IEX/Mimikatz)"),
        (r"(?i)(downloadstring|downloadfile)",        "remote payload download"),
        (r"(?i)(-nop\b|-w\s+hidden)",                "no-profile / hidden"),
    ]

    explanations = []
    for ev in events:
        if ev["event_id"] not in detected_ids:
            continue
        if ev.get("sourcetype") != "sysmon":
            continue

        process = ev.get("process", "").lower()
        if "powershell" not in process and "pwsh" not in process:
            continue

        cmd = ev.get("command_line", "")
        matched = []
        for pattern, label in PATTERNS:
            if re.search(pattern, cmd):
                matched.append(label)

        reason = (
            f"Suspicious PowerShell execution by {ev.get('user', 'unknown')} "
            f"from parent {ev.get('parent_process', 'unknown')}: "
            + (", ".join(matched) if matched else "suspicious command")
        )

        features = {
            "process":          ev.get("process"),
            "parent_process":   ev.get("parent_process"),
            "user":             ev.get("user"),
            "matched_patterns": matched,
            "command_excerpt":  cmd[:120],
        }

        explanations.append(_make_explanation(
            ev["event_id"], "RULE-005", "PowerShell Abuse", "T1059.001", reason, features
        ))

    return explanations


def explain_privilege_escalation(events: List[Dict], detected_ids: Set[str]) -> List[Dict]:
    """Explain privilege escalation detections with command and user context."""
    explanations = []
    for ev in events:
        if ev["event_id"] not in detected_ids:
            continue
        if ev.get("action") != "escalation":
            continue

        cmd   = ev.get("command", "")
        user  = ev.get("user", "unknown")
        reason = f"Privilege escalation by {user}: {cmd[:80]}"
        features = {
            "user":    user,
            "command": cmd,
            "src_ip":  ev.get("src_ip"),
        }
        explanations.append(_make_explanation(
            ev["event_id"], "RULE-006", "Privilege Escalation", "T1068", reason, features
        ))

    return explanations


def explain_fileless_lolbins(events: List[Dict], detected_ids: Set[str]) -> List[Dict]:
    """Explain fileless LOLBin detections with binary name and triggered pattern."""
    from detect import FILELESS_PATTERNS  # type: ignore
    import re

    explanations = []
    for ev in events:
        if ev["event_id"] not in detected_ids:
            continue
        if ev.get("sourcetype") != "sysmon":
            continue

        process = ev.get("process", "").lower()
        cmd     = ev.get("command_line", "")
        patterns = FILELESS_PATTERNS.get(process, [])

        matched = [p for p in patterns if re.search(p, cmd, re.IGNORECASE)]

        reason = (
            f"Fileless execution via {process}: "
            + (", ".join(matched[:3]) if matched else "suspicious command")
        )

        features = {
            "process":          ev.get("process"),
            "parent_process":   ev.get("parent_process"),
            "user":             ev.get("user"),
            "matched_patterns": matched,
            "command_excerpt":  cmd[:120],
        }
        explanations.append(_make_explanation(
            ev["event_id"], "RULE-007", "Fileless LOLBins", "T1218", reason, features
        ))

    return explanations


# ═══ Aggregation ════════════════════════════════════════════════════════════

# Map RULE IDs → explainer functions
_EXPLAINERS = {
    "RULE-001": explain_brute_force,
    "RULE-002": explain_dns_exfiltration,
    "RULE-003": explain_c2_beaconing,
    "RULE-004": explain_lateral_movement,
    "RULE-005": explain_powershell_abuse,
    "RULE-006": explain_privilege_escalation,
    "RULE-007": explain_fileless_lolbins,
}


def explain_all(
    events: List[Dict],
    rule_results: Dict[str, List[str]],
) -> List[Dict]:
    """
    Dispatch to per-rule explainers and return a flat list of explanation
    records, deduplicated on event_id (first explainer wins if multiple rules
    fire on the same event).
    """
    seen: Set[str] = set()
    explanations: List[Dict] = []

    for rule_id, detected_ids in rule_results.items():
        if not detected_ids:
            continue
        explainer = _EXPLAINERS.get(rule_id)
        if explainer is None:
            # Produce minimal explanations for OpenClaw rules (101-110) without
            # a dedicated function yet.
            for eid in detected_ids:
                if eid not in seen:
                    seen.add(eid)
                    explanations.append({
                        "event_id":  eid,
                        "rule_id":   rule_id,
                        "rule_name": rule_id,
                        "mitre":     "",
                        "mitre_url": "",
                        "reason":    f"Detected by {rule_id}",
                        "features":  {},
                        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                    })
            continue

        detected_set = set(detected_ids)
        for exp in explainer(events, detected_set):
            if exp["event_id"] not in seen:
                seen.add(exp["event_id"])
                explanations.append(exp)

    explanations.sort(key=lambda x: x["rule_id"])
    return explanations


# ═══ Output ═════════════════════════════════════════════════════════════════

def write_explanations(
    explanations: List[Dict],
    path: str = EXPLANATIONS_FILE,
) -> None:
    """Persist explanation set to disk."""
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"count": len(explanations), "explanations": explanations}, fh, indent=2)


def format_markdown(explanations: List[Dict], max_rows: int = 50) -> str:
    """Render explanations as a Markdown table (up to max_rows rows)."""
    if not explanations:
        return "_No detections to explain._"

    header = "| Event ID | Rule | MITRE | Reason |\n|---|---|---|---|\n"
    rows = []
    for exp in explanations[:max_rows]:
        mitre_link = (
            f"[{exp['mitre']}]({exp['mitre_url']})" if exp.get("mitre_url") else exp.get("mitre", "")
        )
        reason = exp.get("reason", "").replace("|", "\\|")
        rows.append(
            f"| `{exp['event_id']}` | {exp.get('rule_name', exp['rule_id'])} "
            f"| {mitre_link} | {reason} |"
        )

    footer = (
        f"\n_Showing {max_rows} of {len(explanations)} detections._"
        if len(explanations) > max_rows
        else ""
    )
    return header + "\n".join(rows) + footer
