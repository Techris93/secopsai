from __future__ import annotations

import json
import math
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MEMORY_PATH = ROOT / "data" / "biological_intelligence" / "threat_memory.json"

SEVERITY_SCORE = {
    "info": 5,
    "low": 20,
    "medium": 45,
    "high": 75,
    "critical": 95,
}

NATURE_MODELS = [
    {
        "model": "immune_system",
        "principle": "detect_isolate_remember",
        "implementation": "Innate rules flag obvious threats, adaptive memory raises sensitivity for recurring patterns, and high-risk entities receive containment actions.",
    },
    {
        "model": "ant_colonies",
        "principle": "swarm_intelligence_pheromone_trails",
        "implementation": "Repeated incident traits leave decaying confidence trails that influence future prioritization.",
    },
    {
        "model": "mycelium_networks",
        "principle": "distributed_sensing_resource_routing",
        "implementation": "Weak signals across users, hosts, packages, sessions, rules, and sources are clustered into shared risk corridors.",
    },
    {
        "model": "flocking_birds",
        "principle": "local_rules_coordinated_behavior",
        "implementation": "Simple alert-agent heuristics coordinate triage without requiring a monolithic global decision.",
    },
    {
        "model": "predator_prey_cycles",
        "principle": "adversarial_adaptation",
        "implementation": "Top attacker traits generate red-team/blue-team simulation scenarios for vaccination.",
    },
    {
        "model": "skin",
        "principle": "layered_defense_self_healing",
        "implementation": "Blast containment, access tightening, logging escalation, and patch checks form a regenerating defense barrier.",
    },
    {
        "model": "circadian_rhythm",
        "principle": "timing_matters",
        "implementation": "Off-hours, weekend, and clustered timing patterns raise anomaly sensitivity.",
    },
    {
        "model": "tree_roots",
        "principle": "resource_prioritization",
        "implementation": "Attention is allocated to the highest-risk assets and recurring shared roots first.",
    },
    {
        "model": "echolocation",
        "principle": "active_probing",
        "implementation": "Safe probes are recommended to validate suspected weak points without destructive testing.",
    },
    {
        "model": "octopus_camouflage",
        "principle": "context_aware_deception",
        "implementation": "High-interest assets receive honeypot and deception recommendations tuned to attacker behavior.",
    },
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _severity_value(finding: Dict[str, Any]) -> int:
    if finding.get("severity_score") is not None:
        try:
            return int(finding["severity_score"])
        except (TypeError, ValueError):
            pass
    return SEVERITY_SCORE.get(str(finding.get("severity") or "info").lower(), 5)


def _finding_entities(finding: Dict[str, Any]) -> List[Tuple[str, str]]:
    candidates = [
        ("package", finding.get("package")),
        ("ecosystem", finding.get("ecosystem")),
        ("platform", finding.get("platform")),
        ("source", finding.get("source")),
        ("user", finding.get("user") or finding.get("username") or finding.get("actor")),
        ("host", finding.get("host") or finding.get("hostname") or finding.get("endpoint")),
        ("session", finding.get("session_key") or finding.get("session_id")),
    ]
    for event in finding.get("events") or []:
        if not isinstance(event, dict):
            continue
        candidates.extend(
            [
                ("user", event.get("user") or event.get("username") or event.get("actor")),
                ("host", event.get("host") or event.get("hostname") or event.get("endpoint")),
                ("session", event.get("session_key") or event.get("session_id")),
            ]
        )

    entities = [
        (kind, str(value))
        for kind, value in candidates
        if value not in {None, "", "None"}
    ]
    for rule_id in finding.get("rule_ids") or []:
        entities.append(("rule", str(rule_id)))
    return sorted(set(entities))

def _trait_key(kind: str, value: str) -> str:
    return f"{kind}:{value}".lower()


def _finding_trait_keys(finding: Dict[str, Any]) -> List[str]:
    traits = [_trait_key(kind, value) for kind, value in _finding_entities(finding)]
    severity = str(finding.get("severity") or "unknown").lower()
    traits.append(f"severity:{severity}")
    category = str(finding.get("category") or finding.get("platform") or finding.get("source") or "unknown").lower()
    traits.append(f"category:{category}")
    return sorted(set(traits))


def _load_json(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    if not path.exists():
        return default
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default
    return payload if isinstance(payload, dict) else default


def load_threat_memory(path: str | Path | None = None) -> Dict[str, Any]:
    return _load_json(Path(path or DEFAULT_MEMORY_PATH), {"memory_cells": {}, "pheromone_trails": {}})


def save_threat_memory(memory: Dict[str, Any], path: str | Path | None = None) -> str:
    target = Path(path or DEFAULT_MEMORY_PATH)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(memory, indent=2, sort_keys=True), encoding="utf-8")
    return str(target)


def _decay_trails(memory: Dict[str, Any], half_life_days: float = 14.0) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    trails = memory.get("pheromone_trails") if isinstance(memory.get("pheromone_trails"), dict) else {}
    decayed: Dict[str, Any] = {}
    for key, trail in trails.items():
        if not isinstance(trail, dict):
            continue
        last_seen = _parse_time(trail.get("last_seen")) or now
        age_days = max(0.0, (now - last_seen).total_seconds() / 86400)
        decay = math.pow(0.5, age_days / half_life_days)
        strength = max(0.0, float(trail.get("strength") or 0) * decay)
        if strength >= 0.05:
            decayed[key] = {**trail, "strength": round(strength, 4)}
    return decayed


def _update_memory(findings: List[Dict[str, Any]], memory: Dict[str, Any]) -> Dict[str, Any]:
    updated = {
        "generated_at": _utc_now(),
        "memory_cells": dict(memory.get("memory_cells") or {}),
        "pheromone_trails": _decay_trails(memory),
    }
    for finding in findings:
        finding_id = str(finding.get("finding_id") or finding.get("id") or "")
        score = _severity_value(finding)
        observed_at = str(finding.get("last_seen") or finding.get("first_seen") or _utc_now())
        for trait in _finding_trait_keys(finding):
            trail = updated["pheromone_trails"].get(trait, {"strength": 0.0, "hits": 0})
            trail["strength"] = round(float(trail.get("strength") or 0.0) + score / 100.0, 4)
            trail["hits"] = int(trail.get("hits") or 0) + 1
            trail["last_seen"] = observed_at
            updated["pheromone_trails"][trait] = trail

            cell = updated["memory_cells"].get(trait, {"hits": 0, "finding_ids": []})
            cell["hits"] = int(cell.get("hits") or 0) + 1
            ids = [str(item) for item in cell.get("finding_ids") or []]
            if finding_id and finding_id not in ids:
                ids.append(finding_id)
            cell["finding_ids"] = ids[-25:]
            cell["last_observed"] = observed_at
            cell["max_severity_score"] = max(int(cell.get("max_severity_score") or 0), score)
            updated["memory_cells"][trait] = cell
    return updated


def _cluster_findings(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    clusters: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        for kind, value in _finding_entities(finding):
            clusters[_trait_key(kind, value)].append(finding)
    return {
        key: rows
        for key, rows in clusters.items()
        if len(rows) >= 2
    }


def _off_hours_signal(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    observed_at = _parse_time(finding.get("last_seen") or finding.get("first_seen"))
    if observed_at is None:
        return None
    hour = observed_at.hour
    if hour < 6 or hour >= 20 or observed_at.weekday() >= 5:
        return {
            "finding_id": finding.get("finding_id"),
            "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
            "reason": "off_hours_or_weekend_activity",
            "risk_lift": 8 if observed_at.weekday() < 5 else 12,
        }
    return None


def _recommend_containment(finding: Dict[str, Any], score: int, clustered: bool) -> List[str]:
    actions: List[str] = []
    if score >= 90:
        actions.append("isolate affected session, user, endpoint, package, or API key until reviewed")
        actions.append("tighten access controls and increase audit logging for the blast radius")
    elif score >= 75:
        actions.append("move finding into in_review and collect host/package evidence")
        actions.append("increase telemetry sampling for related entities")
    elif clustered:
        actions.append("raise sensitivity for recurring related entities")
    if "supply" in str(finding.get("source") or finding.get("platform") or "").lower():
        actions.append("pin dependency versions and verify package provenance before promotion")
    return actions


def evaluate_security_biology(
    findings: Iterable[Dict[str, Any]],
    *,
    memory: Optional[Dict[str, Any]] = None,
    memory_path: str | Path | None = None,
    persist_memory: bool = False,
) -> Dict[str, Any]:
    rows = [dict(finding) for finding in findings]
    previous_memory = memory if memory is not None else load_threat_memory(memory_path)
    updated_memory = _update_memory(rows, previous_memory)
    clusters = _cluster_findings(rows)

    severity_counts = Counter(str(row.get("severity") or "unknown").lower() for row in rows)
    critical_or_high = sum(1 for row in rows if _severity_value(row) >= 75)
    cluster_risk = sum(len(value) for value in clusters.values())
    immune_active = critical_or_high >= 2 or any(_severity_value(row) >= 90 for row in rows) or cluster_risk >= 4
    sensitivity_multiplier = 1.0 + min(1.5, critical_or_high * 0.15 + cluster_risk * 0.04)

    cluster_keys = set(clusters)
    finding_assessments: List[Dict[str, Any]] = []
    for finding in rows:
        traits = _finding_trait_keys(finding)
        clustered = any(trait in cluster_keys for trait in traits)
        circadian = _off_hours_signal(finding)
        score = _severity_value(finding)
        trail_strength = sum(
            float(updated_memory.get("pheromone_trails", {}).get(trait, {}).get("strength") or 0.0)
            for trait in traits
        )
        adaptive_score = min(100, round(score + min(20, trail_strength * 2) + (circadian or {}).get("risk_lift", 0)))
        containment = _recommend_containment(finding, score, clustered)
        finding_assessments.append(
            {
                "finding_id": finding.get("finding_id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "base_score": score,
                "adaptive_score": adaptive_score,
                "clustered": clustered,
                "memory_traits": traits[:10],
                "recommended_state": "immune_response" if adaptive_score >= 85 else "watch" if adaptive_score >= 55 else "baseline",
                "containment_actions": containment,
                "circadian_signal": circadian,
            }
        )

    high_interest_traits = [
        key
        for key, trail in sorted(
            updated_memory.get("pheromone_trails", {}).items(),
            key=lambda item: float(item[1].get("strength") or 0.0),
            reverse=True,
        )
        if not key.startswith("severity:")
    ][:8]
    top_clusters = [
        {
            "trait": trait,
            "finding_ids": [str(row.get("finding_id")) for row in clustered_rows],
            "max_severity_score": max(_severity_value(row) for row in clustered_rows),
        }
        for trait, clustered_rows in sorted(
            clusters.items(),
            key=lambda item: (max(_severity_value(row) for row in item[1]), len(item[1])),
            reverse=True,
        )[:8]
    ]
    root_priorities = sorted(
        (
            {
                "trait": item["trait"],
                "priority_score": min(100, item["max_severity_score"] + len(item["finding_ids"]) * 5),
                "finding_ids": item["finding_ids"],
            }
            for item in top_clusters
        ),
        key=lambda item: item["priority_score"],
        reverse=True,
    )
    circadian_signals = [item["circadian_signal"] for item in finding_assessments if item["circadian_signal"]]
    red_team_traits = [
        trait
        for trait in high_interest_traits
        if trait.startswith(("rule:", "package:", "host:", "platform:", "source:"))
    ][:5]

    payload = {
        "generated_at": _utc_now(),
        "design_principle": "Biological Intelligence Layer",
        "loop": ["observe", "detect_pattern", "adapt_response", "remember_outcome"],
        "nature_models": NATURE_MODELS,
        "sensing": {
            "findings": len(rows),
            "severity_counts": dict(severity_counts),
            "clustered_traits": len(clusters),
        },
        "immune_system": {
            "mode": "active" if immune_active else "baseline",
            "sensitivity_multiplier": round(sensitivity_multiplier, 2),
            "innate_immunity": "severity, policy, and known rule scoring",
            "adaptive_immunity": "decaying threat memory and repeated trait reinforcement",
            "memory_cells": len(updated_memory.get("memory_cells", {})),
            "inflammation_response": "cluster sensitivity raised" if cluster_risk else "normal sensitivity",
            "apoptosis": "auto-isolate critical clustered entities" if immune_active else "manual containment only",
            "vaccination": [f"simulate attacker path around {trait}" for trait in red_team_traits],
        },
        "ant_colonies": {
            "pheromone_trails": [
                {"trait": trait, **trail}
                for trait, trail in sorted(
                    updated_memory.get("pheromone_trails", {}).items(),
                    key=lambda item: float(item[1].get("strength") or 0.0),
                    reverse=True,
                )[:10]
            ]
        },
        "mycelium_networks": {"weak_signal_clusters": top_clusters},
        "flocking_birds": {
            "agent_rules": [
                "critical clustered finding -> isolate first, investigate second",
                "repeated benign low-risk pattern -> tune policy instead of escalating",
                "single high-risk supply-chain package -> verify dependency presence and provenance",
                "multiple off-hours events -> raise queue priority for analyst review",
            ]
        },
        "predator_prey_cycles": {
            "red_blue_simulations": [
                {
                    "scenario": f"adversary adapts around {trait}",
                    "blue_team_response": "tighten detection, run safe replay, preserve evidence, and update memory trails",
                }
                for trait in red_team_traits
            ]
        },
        "skin": {
            "layered_defense": [
                "least-privilege access tightening",
                "blast-radius scoped isolation",
                "extra audit logging while immune mode is active",
                "dependency pinning and provenance checks for supply-chain findings",
            ],
            "self_healing": "close expected behavior with notes, queue risky changes, and keep memory for recurrence",
        },
        "circadian_rhythm": {"time_aware_anomalies": circadian_signals},
        "tree_roots": {"asset_priorities": root_priorities},
        "echolocation": {
            "safe_probes": [
                {
                    "trait": trait,
                    "probe": "run non-destructive presence check, dependency lookup, or telemetry query for the related entity",
                }
                for trait in high_interest_traits[:6]
            ]
        },
        "octopus_camouflage": {
            "deception_recommendations": [
                {
                    "trait": trait,
                    "control": "place honeypot credential, canary package, or decoy workflow near the observed attacker path",
                }
                for trait in high_interest_traits[:5]
            ]
        },
        "findings": sorted(finding_assessments, key=lambda item: item["adaptive_score"], reverse=True),
        "memory": updated_memory,
    }
    if persist_memory:
        payload["memory_path"] = save_threat_memory(updated_memory, memory_path)
    return payload
