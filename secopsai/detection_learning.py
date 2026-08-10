"""Guarded offline learning for SecOpsAI detection and investigation policy.

Only evidence-backed outcomes become labels. Learning output is inert until it
passes replay, holdout, shadow, and canary gates. No model text is ground truth.
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
from contextlib import closing
from typing import Any, Dict, Optional

import soc_store

SCHEMA_VERSION = "secopsai.detection-learning.v1"
FEATURE_VERSION = "dlf-1"
MODES = {"off", "advisory", "guarded"}
# ``outcome`` describes what happened to an alert or evaluation.  The model
# still trains on the binary ``learning_label`` because TP/FN are evidence of
# the threat class and FP/TN are evidence of the benign class.  ``unknown``
# is retained for active learning, but is never used as ground truth.
OUTCOMES = {"true_positive", "false_positive", "true_negative", "false_negative", "unknown"}
LABELS = {"true_positive", "false_positive"}
OUTCOME_TO_LABEL = {
    "true_positive": "true_positive",
    "false_negative": "true_positive",
    "false_positive": "false_positive",
    "true_negative": "false_positive",
}
TRUSTED_FEEDBACK_SOURCES = {
    "evidence_gated_research_resolution",
    "evidence_linked_research_verdict",
    "corroborated_agent_escalation",
    "operator_verified",
    "operator_reviewed_disposition",
    "sandbox_confirmed",
    "external_advisory",
    "rule_fixture",
}
FEATURES = ("severity", "rule_count", "event_count", "advisory", "denylisted", "strong_signals", "static_evidence", "active_iocs", "sandbox_evidence")
DEFAULTS = {"mode": "advisory", "minimum_examples": 20, "holdout_percent": 20, "maximum_false_negative_regression": 0, "minimum_precision": 0.90, "canary_percent": 10, "auto_promote_shadow": False, "auto_promote_canary": False}


def _json(v: Any) -> str: return json.dumps(v, sort_keys=True, separators=(",", ":"))
def _decode(v: Any, default: Any) -> Any:
    try: return json.loads(str(v or ""))
    except (TypeError, ValueError, json.JSONDecodeError): return default
def _id(prefix: str) -> str: return f"{prefix}-{secrets.token_hex(8).upper()}"
def _clean(v: Any, n: int = 4000) -> str: return str(v or "").strip()[:n]


def get_settings(*, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as c:
        row = c.execute("SELECT * FROM detection_learning_settings WHERE settings_id=1").fetchone()
        if row is None:
            now = soc_store.utc_now()
            c.execute("""INSERT INTO detection_learning_settings VALUES
                (1,?,?,?,?,?,?,?,?,?,?)""", (DEFAULTS["mode"], DEFAULTS["minimum_examples"], DEFAULTS["holdout_percent"], DEFAULTS["maximum_false_negative_regression"], DEFAULTS["minimum_precision"], DEFAULTS["canary_percent"], 0, 0, now, "secopsai-default"))
            c.commit(); row = c.execute("SELECT * FROM detection_learning_settings WHERE settings_id=1").fetchone()
    out = dict(row or {}); out["auto_promote_shadow"] = bool(out.get("auto_promote_shadow")); out["auto_promote_canary"] = bool(out.get("auto_promote_canary")); out["schema_version"] = SCHEMA_VERSION; return out


def update_settings(*, mode: Optional[str] = None, minimum_examples: Optional[int] = None,
                    holdout_percent: Optional[int] = None, maximum_false_negative_regression: Optional[int] = None,
                    minimum_precision: Optional[float] = None, canary_percent: Optional[int] = None,
                    auto_promote_shadow: Optional[bool] = None, auto_promote_canary: Optional[bool] = None,
                    actor: str = "operator", db_path: Optional[str] = None) -> Dict[str, Any]:
    s = get_settings(db_path=db_path); m = _clean(mode if mode is not None else s["mode"], 20).lower()
    values = (int(minimum_examples if minimum_examples is not None else s["minimum_examples"]), int(holdout_percent if holdout_percent is not None else s["holdout_percent"]), int(maximum_false_negative_regression if maximum_false_negative_regression is not None else s["maximum_false_negative_regression"]), float(minimum_precision if minimum_precision is not None else s["minimum_precision"]), int(canary_percent if canary_percent is not None else s["canary_percent"]))
    if m not in MODES or not 10 <= values[0] <= 100000 or not 10 <= values[1] <= 40 or not 0 <= values[2] <= 10 or not .5 <= values[3] <= 1 or not 1 <= values[4] <= 50: raise ValueError("invalid detection learning policy")
    shadow = bool(auto_promote_shadow if auto_promote_shadow is not None else s["auto_promote_shadow"]); canary = bool(auto_promote_canary if auto_promote_canary is not None else s["auto_promote_canary"])
    if (shadow or canary) and m != "guarded": raise ValueError("automatic promotion requires guarded mode")
    with closing(soc_store.connect(db_path)) as c:
        c.execute("""UPDATE detection_learning_settings SET mode=?,minimum_examples=?,holdout_percent=?,maximum_false_negative_regression=?,minimum_precision=?,canary_percent=?,auto_promote_shadow=?,auto_promote_canary=?,updated_at=?,updated_by=? WHERE settings_id=1""", (m,*values,int(shadow),int(canary),soc_store.utc_now(),_clean(actor,160))); c.commit()
    return get_settings(db_path=db_path)


def _split(key: str, holdout: int) -> str:
    bucket = int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % 100
    return "holdout" if bucket < holdout else ("validation" if bucket < holdout + 20 else "train")


def _feature_values(features: Any) -> Dict[str, float]:
    values = features if isinstance(features, dict) else {}
    normalized: Dict[str, float] = {}
    for key in FEATURES:
        try:
            normalized[key] = max(0.0, min(1.0, float(values.get(key, 0.0))))
        except (TypeError, ValueError):
            normalized[key] = 0.0
    return normalized


def _feedback_dedupe(*, organization_key: str, subject_key: str, outcome: str,
                     label_source: str, feature_version: str, event_id: str,
                     evidence_refs: list[str]) -> str:
    payload = _json({
        "organization_key": organization_key,
        "subject_key": subject_key,
        "outcome": outcome,
        "label_source": label_source,
        "feature_version": feature_version,
        "event_id": event_id,
        "evidence_refs": sorted(set(evidence_refs)),
    })
    return hashlib.sha256(payload.encode()).hexdigest()


def _insert_feedback(
    connection: Any,
    *,
    organization_key: str,
    subject_key: str,
    finding_id: str,
    event_id: str,
    outcome: str,
    label_source: str,
    confidence: int,
    trust_score: int,
    features: Dict[str, float],
    evidence_refs: list[str],
    metadata: Dict[str, Any],
    actor: str,
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    outcome = _clean(outcome, 40).lower()
    if outcome not in OUTCOMES:
        raise ValueError(f"invalid feedback outcome: {outcome}")
    subject_key = _clean(subject_key or finding_id, 240)
    if not subject_key:
        raise ValueError("subject_key or finding_id is required")
    organization_key = _clean(organization_key or "local", 160)
    label_source = _clean(label_source or "operator", 160)
    actor = _clean(actor or "operator", 160)
    finding_id = _clean(finding_id, 160)
    event_id = _clean(event_id, 200)
    confidence = max(0, min(100, int(confidence or 0)))
    trust_score = max(0, min(100, int(trust_score or confidence)))
    refs = [_clean(item, 200) for item in evidence_refs if _clean(item, 200)]
    values = _feature_values(features)
    learning_label = OUTCOME_TO_LABEL.get(outcome)
    eligible = bool(
        learning_label
        and label_source in TRUSTED_FEEDBACK_SOURCES
        and confidence >= 70
        and trust_score >= 70
    )
    dedupe_key = _feedback_dedupe(
        organization_key=organization_key,
        subject_key=subject_key,
        outcome=outcome,
        label_source=label_source,
        feature_version=FEATURE_VERSION,
        event_id=event_id,
        evidence_refs=refs,
    )
    now = soc_store.utc_now()
    feedback_id = _id("DLF")
    cursor = connection.execute(
        """INSERT OR IGNORE INTO detection_learning_feedback
           (feedback_id, organization_key, subject_key, finding_id, event_id,
            outcome, learning_label, label_source, confidence, trust_score,
            feature_version, features_json, evidence_refs_json, metadata_json,
            actor, dedupe_key, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            feedback_id, organization_key, subject_key, finding_id or None,
            event_id or None, outcome, learning_label, label_source,
            confidence, trust_score, FEATURE_VERSION, _json(values),
            _json(refs), _json(metadata if isinstance(metadata, dict) else {}),
            actor, dedupe_key, now,
        ),
    )
    inserted = cursor.rowcount > 0
    example_id = None
    if inserted and eligible and learning_label:
        example_finding_id = finding_id or subject_key
        example_id = "DLE-" + hashlib.sha256(
            f"{organization_key}|{example_finding_id}|{FEATURE_VERSION}".encode()
        ).hexdigest()[:16].upper()
        connection.execute(
            """INSERT INTO detection_learning_examples
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(organization_key,finding_id,feature_version) DO UPDATE SET
                 label=excluded.label,
                 label_source=excluded.label_source,
                 trust_score=excluded.trust_score,
                 features_json=excluded.features_json,
                 evidence_refs_json=excluded.evidence_refs_json,
                 updated_at=excluded.updated_at""",
            (
                example_id, organization_key, example_finding_id,
                metadata.get("case_id") if isinstance(metadata, dict) else None,
                learning_label, label_source, trust_score, FEATURE_VERSION,
                _json(values), _split(example_finding_id, int(settings["holdout_percent"])),
                _json(refs), now, now,
            ),
        )
    return {
        "feedback_id": feedback_id if inserted else None,
        "inserted": inserted,
        "outcome": outcome,
        "learning_label": learning_label,
        "eligible_for_training": eligible,
        "example_id": example_id,
        "dedupe_key": dedupe_key,
    }


def record_feedback(*, outcome: str, subject_key: str = "", finding_id: str = "",
                    event_id: str = "", source: str = "operator_verified",
                    confidence: int = 0, trust_score: int = 0,
                    evidence_refs: Optional[list[str]] = None,
                    features: Optional[Dict[str, Any]] = None,
                    metadata: Optional[Dict[str, Any]] = None,
                    actor: str = "operator", organization_key: str = "local",
                    db_path: Optional[str] = None) -> Dict[str, Any]:
    """Persist one immutable outcome and optionally promote it to training.

    All outcomes are retained.  Only an explicit trusted source can create a
    binary training example.  This prevents unresolved alerts and model-only
    suggestions from becoming labels while still preserving them for active
    learning and later adjudication.
    """
    soc_store.init_db(db_path)
    settings = get_settings(db_path=db_path)
    finding: Dict[str, Any] = {}
    if finding_id:
        finding = soc_store.get_finding(finding_id, db_path) or {}
    with closing(soc_store.connect(db_path)) as connection:
        linked = connection.execute(
            "SELECT case_id FROM research_case_findings WHERE finding_id=? ORDER BY created_at DESC LIMIT 1",
            (_clean(finding_id, 160),),
        ).fetchone() if finding_id else None
        case_id = str(linked["case_id"]) if linked else ""
        values = features if features is not None else _features(finding, connection, case_id)
        item = _insert_feedback(
            connection,
            organization_key=organization_key,
            subject_key=subject_key or finding_id,
            finding_id=finding_id,
            event_id=event_id,
            outcome=outcome,
            label_source=source,
            confidence=confidence,
            trust_score=trust_score or confidence,
            features=values,
            evidence_refs=evidence_refs or [],
            metadata={**(metadata or {}), "case_id": case_id} if case_id else (metadata or {}),
            actor=actor,
            settings=settings,
        )
        connection.commit()
    return item


def _trusted_label(finding: Dict[str, Any], connection: Any) -> Optional[tuple[str,str,int,str]]:
    fid = _clean(finding.get("finding_id"), 160); disposition = _clean(finding.get("disposition"), 40).lower()
    linked = connection.execute("SELECT case_id FROM research_case_findings WHERE finding_id=? ORDER BY created_at DESC LIMIT 1", (fid,)).fetchone()
    case_id = str(linked["case_id"]) if linked else ""
    if case_id:
        resolution = connection.execute("SELECT status,verdict,confidence,run_id FROM research_resolution_runs WHERE case_id=? AND status IN ('applied','reviewed') ORDER BY updated_at DESC LIMIT 1", (case_id,)).fetchone()
        if resolution and str(resolution["verdict"]) in {"not_substantiated","benign"}: return "false_positive", "evidence_gated_research_resolution", max(90,int(resolution["confidence"])), case_id
        verdict = connection.execute("SELECT verdict,confidence,actor FROM research_verdicts WHERE case_id=? ORDER BY created_at DESC LIMIT 1", (case_id,)).fetchone()
        if verdict and str(verdict["verdict"]) in {"likely","credible"} and int(verdict["confidence"]) >= 80: return "true_positive", "evidence_linked_research_verdict", int(verdict["confidence"]), case_id
    if disposition in {"false_positive", "expected_behavior", "not_applicable", "accepted_risk"}:
        return "false_positive", "operator_reviewed_disposition", 90, case_id
    if disposition in {"remediated","true_positive"}:
        triage = connection.execute("SELECT final_action,decision_json FROM agent_triage_runs WHERE target_id=? AND status='escalated' ORDER BY updated_at DESC LIMIT 1", (fid,)).fetchone()
        if triage:
            decision = _decode(triage["decision_json"], {})
            if int(decision.get("model_confidence") or 0) >= 85 and decision.get("validated_evidence_refs"): return "true_positive", "corroborated_agent_escalation", int(decision["model_confidence"]), case_id
    return None


def _features(f: Dict[str, Any], c: Any, case_id: str) -> Dict[str,float]:
    evidence = f.get("evidence") if isinstance(f.get("evidence"),dict) else {}; threat = evidence.get("threat_assessment") if isinstance(evidence.get("threat_assessment"),dict) else {}
    sev = {"info":0,"low":.25,"medium":.5,"high":.75,"critical":1}.get(_clean(f.get("severity"),20).lower(),0)
    counts = {"static":0,"ioc":0,"sandbox":0}
    if case_id:
        counts["static"] = int(c.execute("SELECT COUNT(*) FROM research_evidence WHERE case_id=? AND evidence_type='static_analysis' AND status='active'",(case_id,)).fetchone()[0])
        counts["ioc"] = int(c.execute("SELECT COUNT(*) FROM research_iocs WHERE case_id=? AND status='active' AND confidence>=80",(case_id,)).fetchone()[0])
        counts["sandbox"] = int(c.execute("SELECT COUNT(*) FROM research_evidence WHERE case_id=? AND evidence_type='sandbox_analysis' AND status='active'",(case_id,)).fetchone()[0])
    return {"severity":sev,"rule_count":min(len(f.get("rule_ids") or [])/5,1),"event_count":min(len(f.get("event_ids") or [])/10,1),"advisory":float(bool(threat.get("advisory_backed") or evidence.get("advisory_backed"))),"denylisted":float(bool(threat.get("denylisted") or evidence.get("denylisted"))),"strong_signals":min(len(threat.get("strong_signals") or evidence.get("strong_signals") or [])/5,1),"static_evidence":min(counts["static"]/3,1),"active_iocs":min(counts["ioc"]/3,1),"sandbox_evidence":float(bool(counts["sandbox"]))}


def collect_examples(*, organization_key: str = "local", db_path: Optional[str] = None) -> Dict[str,Any]:
    settings=get_settings(db_path=db_path); inserted=0; excluded=0; observed=0; feedback_inserted=0; unresolved=0
    findings=soc_store.list_findings(db_path,limit=None,include_payload=True)
    with closing(soc_store.connect(db_path)) as c:
        for f in findings:
            observed += 1
            trusted=_trusted_label(f,c)
            fid=_clean(f.get("finding_id"),160)
            linked = c.execute("SELECT case_id FROM research_case_findings WHERE finding_id=? ORDER BY created_at DESC LIMIT 1", (fid,)).fetchone()
            case_id = str(linked["case_id"]) if linked else ""
            feats = _features(f,c,case_id)
            refs = [fid] + list(f.get("rule_ids") or []) + list(f.get("event_ids") or [])
            if trusted:
                label,source,trust,case_id=trusted
                outcome = label
                confidence = trust
                metadata = {"case_id": case_id, "original_disposition": f.get("disposition"), "automatic": True}
            else:
                outcome = "unknown"
                source = "alert_observed"
                trust = 0
                confidence = 0
                metadata = {"original_disposition": f.get("disposition"), "automatic": True, "active_learning": True}
            item = _insert_feedback(
                c,
                organization_key=organization_key,
                subject_key=fid,
                finding_id=fid,
                event_id=str((f.get("event_ids") or [""])[0] or ""),
                outcome=outcome,
                label_source=source,
                confidence=confidence,
                trust_score=trust,
                features=feats,
                evidence_refs=refs,
                metadata=metadata,
                actor="secopsai-learning",
                settings=settings,
            )
            if item["inserted"]:
                feedback_inserted += 1
            if outcome == "unknown":
                unresolved += 1
            if item["eligible_for_training"]:
                inserted += 1
            else:
                excluded += 1
        c.commit()
    return {
        "accepted": inserted,
        "observed_alerts": observed,
        "feedback_inserted": feedback_inserted,
        "unresolved_feedback": unresolved,
        "excluded_untrusted": excluded,
        "policy": "all alerts retained; only trusted outcomes become training labels; unknown/model-only outcomes remain active-learning feedback",
    }


def _rows(db_path: Optional[str]) -> list[Dict[str,Any]]:
    with closing(soc_store.connect(db_path)) as c: rows=c.execute("SELECT * FROM detection_learning_examples ORDER BY example_id").fetchall()
    return [{**dict(r),"features":_decode(r["features_json"],{}),"evidence_refs":_decode(r["evidence_refs_json"],[])} for r in rows]


def snapshot(*, db_path: Optional[str]=None) -> Dict[str,Any]:
    rows=_rows(db_path); fp=hashlib.sha256(_json([(r["example_id"],r["label"],r["updated_at"]) for r in rows]).encode()).hexdigest(); did="DLS-"+fp[:16].upper(); labels={x:sum(r["label"]==x for r in rows) for x in LABELS}; splits={x:sum(r["split"]==x for r in rows) for x in ("train","validation","holdout")}; now=soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as c:
        c.execute("INSERT OR IGNORE INTO detection_learning_datasets VALUES (?,?,?,?,?,?,?,?,?)",(did,SCHEMA_VERSION,FEATURE_VERSION,fp,len(rows),_json(labels),_json(splits),_json({"trusted_sources":["evidence_gated_research_resolution","evidence_linked_research_verdict","corroborated_agent_escalation"],"model_only_excluded":True}),now)); c.commit()
    return {"dataset_id":did,"fingerprint":fp,"example_count":len(rows),"label_counts":labels,"split_counts":splits}


def _predict(weights: Dict[str,float], f: Dict[str,float]) -> float: return 1/(1+math.exp(-max(-30,min(30,weights["bias"]+sum(weights[k]*float(f.get(k,0)) for k in FEATURES)))))
def _metrics(rows: list[Dict[str,Any]], weights: Dict[str,float]) -> Dict[str,Any]:
    tp=fp=tn=fn=0
    for r in rows:
        pred=_predict(weights,r["features"])>=.5; actual=r["label"]=="true_positive"
        tp+=int(pred and actual); fp+=int(pred and not actual); tn+=int(not pred and not actual); fn+=int(not pred and actual)
    def ratio(numerator: int, denominator: int) -> Optional[float]:
        # A zero denominator is undefined, not a measured zero-percent
        # result. Keeping it explicit prevents an empty holdout from looking
        # like a failed but evaluated detector.
        return None if denominator == 0 else numerator / denominator
    return {
        "tp":tp,"fp":fp,"tn":tn,"fn":fn,
        "precision":ratio(tp,tp+fp),"recall":ratio(tp,tp+fn),
        "false_positive_rate":ratio(fp,fp+tn),"false_negative_rate":ratio(fn,fn+tp),
        "count":len(rows),
    }


def train(*, db_path: Optional[str]=None) -> Dict[str,Any]:
    s=get_settings(db_path=db_path); ds=snapshot(db_path=db_path); rows=_rows(db_path); status="blocked"; weights={"bias":0.0,**{k:0.0 for k in FEATURES}}
    if len(rows)>=int(s["minimum_examples"]) and {r["label"] for r in rows}==LABELS:
        train_rows=[r for r in rows if r["split"]=="train"]
        for _ in range(300):
            grad={k:0.0 for k in weights}
            for r in train_rows:
                err=_predict(weights,r["features"])-(1 if r["label"]=="true_positive" else 0); grad["bias"]+=err
                for k in FEATURES: grad[k]+=err*float(r["features"].get(k,0))
            for k in weights: weights[k]-=.15*grad[k]/max(1,len(train_rows))
        status="evaluated"
    metrics={split:_metrics([r for r in rows if r["split"]==split],weights) for split in ("train","validation","holdout")}; hold=metrics["holdout"]; holdout_evaluable=hold["precision"] is not None and hold["recall"] is not None; training_ready=len(rows)>=int(s["minimum_examples"]) and {r["label"] for r in rows}==LABELS; evaluation_status="evaluated" if training_ready and holdout_evaluable else "insufficient_data"; metrics["evaluation_status"]=evaluation_status; gates={"enough_examples":len(rows)>=int(s["minimum_examples"]),"both_labels":{r["label"] for r in rows}==LABELS,"holdout_evaluable":holdout_evaluable,"precision_pass":bool(holdout_evaluable and hold["precision"]>=float(s["minimum_precision"])),"false_negative_regression_pass":bool(holdout_evaluable and hold["fn"]<=int(s["maximum_false_negative_regression"]))}; passed=all(gates.values()); eid=_id("DLX"); pid=_id("DLP"); now=soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as c:
        c.execute("INSERT INTO detection_learning_experiments VALUES (?,?,?,?,?,?,?,?,?)",(eid,ds["dataset_id"],"interpretable_logistic_ranker_v1","passed" if passed else evaluation_status,_json({"weights":weights,"threshold":.5,"feature_version":FEATURE_VERSION,"evaluation_status":evaluation_status}),_json(metrics),_json(gates),now,now))
        c.execute("INSERT INTO detection_learning_proposals VALUES (?,?,?,?,?,?,?,?,?,?,?)",(pid,eid,"risk_ranker","global","shadow_ready" if passed else "blocked",_json({"weights":weights,"threshold":.5,"evaluation_status":evaluation_status}),_json(metrics),_json({"previous_proposal_id":None}),now,now,None)); c.commit()
    return {"experiment_id":eid,"proposal_id":pid,"status":"shadow_ready" if passed else evaluation_status,"metrics":metrics,"guardrails":gates,"dataset":ds}


def deploy(proposal_id: str, *, stage: str, db_path: Optional[str]=None) -> Dict[str,Any]:
    if stage not in {"shadow","canary","active"}: raise ValueError("stage must be shadow, canary, or active")
    s=get_settings(db_path=db_path)
    with closing(soc_store.connect(db_path)) as c:
        p=c.execute("SELECT * FROM detection_learning_proposals WHERE proposal_id=?",(_clean(proposal_id,40).upper(),)).fetchone()
        if not p: raise ValueError("learning proposal not found")
        metrics=_decode(p["replay_metrics_json"],{}); hold=metrics.get("holdout") or {}; precision=hold.get("precision"); allowed=bool(precision is not None and precision>=float(s["minimum_precision"]) and int(hold.get("fn",999))<=int(s["maximum_false_negative_regression"]))
        expected={"shadow":"shadow_ready","canary":"shadow","active":"canary"}[stage]
        if stage == "active":
            prior = c.execute("SELECT observations_json FROM detection_learning_deployments WHERE proposal_id=? AND stage='canary' AND status='running' ORDER BY updated_at DESC LIMIT 1", (p["proposal_id"],)).fetchone()
            observations = _decode(prior["observations_json"], {}) if prior else {}
            observed = sum(int(observations.get(key, 0)) for key in ("tp","fp","tn","fn"))
            if observed < 20 or int(observations.get("fn", 0)) > int(s["maximum_false_negative_regression"]):
                raise ValueError("canary needs at least 20 reviewed observations with no false-negative regression")
        if str(p["status"])!=expected or not allowed: raise ValueError("proposal has not passed the previous deployment gate")
        did=_id("DLD"); traffic={"shadow":0,"canary":int(s["canary_percent"]),"active":100}[stage]; now=soc_store.utc_now(); c.execute("INSERT INTO detection_learning_deployments VALUES (?,?,?,?,?,?,?,?,?)",(did,p["proposal_id"],stage,traffic,"running",_json({"tp":0,"fp":0,"tn":0,"fn":0}),now,None,now)); c.execute("UPDATE detection_learning_proposals SET status=?,updated_at=?,activated_at=CASE WHEN ?='active' THEN ? ELSE activated_at END WHERE proposal_id=?",(stage,now,stage,now,p["proposal_id"])); c.commit()
    return {"deployment_id":did,"proposal_id":proposal_id,"stage":stage,"traffic_percent":traffic,"status":"running"}


def record_observation(deployment_id: str, *, outcome: str, db_path: Optional[str]=None) -> Dict[str,Any]:
    if outcome not in {"tp","fp","tn","fn"}: raise ValueError("invalid canary outcome")
    s=get_settings(db_path=db_path)
    with closing(soc_store.connect(db_path)) as c:
        d=c.execute("SELECT * FROM detection_learning_deployments WHERE deployment_id=?",(_clean(deployment_id,40).upper(),)).fetchone()
        if not d: raise ValueError("deployment not found")
        obs=_decode(d["observations_json"],{}); obs[outcome]=int(obs.get(outcome,0))+1; status="rolled_back" if int(obs.get("fn",0))>int(s["maximum_false_negative_regression"]) else str(d["status"]); now=soc_store.utc_now(); c.execute("UPDATE detection_learning_deployments SET observations_json=?,status=?,completed_at=CASE WHEN ?='rolled_back' THEN ? ELSE completed_at END,updated_at=? WHERE deployment_id=?",(_json(obs),status,status,now,now,d["deployment_id"]));
        if status=="rolled_back":
            c.execute("UPDATE detection_learning_proposals SET status='rolled_back',updated_at=? WHERE proposal_id=?",(now,d["proposal_id"]))
        c.commit()
    promoted = None
    total = sum(int(obs.get(key, 0)) for key in ("tp","fp","tn","fn"))
    if status != "rolled_back" and str(d["stage"]) == "canary" and total >= 20 and bool(s["auto_promote_canary"]):
        promoted = deploy(str(d["proposal_id"]), stage="active", db_path=db_path)
    return {"deployment_id":deployment_id,"status":status,"observations":obs,"automatic_rollback":status=="rolled_back","automatic_promotion":promoted}


def recommend_action(context: Dict[str,Any], *, db_path: Optional[str]=None) -> Dict[str,Any]:
    soc_store.init_db(db_path)
    actions=("collect_reference","deep_static_analysis","campaign_correlation","model_review","request_sandbox_approval")
    with closing(soc_store.connect(db_path)) as c:
        rows={r["action_name"]:dict(r) for r in c.execute("SELECT * FROM detection_learning_bandit_actions").fetchall()}
    total=sum(int(v["pulls"]) for v in rows.values())+1; scores={}
    for a in actions:
        r=rows.get(a,{"pulls":0,"reward_sum":0}); pulls=int(r["pulls"]); scores[a]=float("inf") if pulls==0 else float(r["reward_sum"])/pulls+math.sqrt(2*math.log(total)/pulls)
    if not context.get("reference_available"): scores["collect_reference"]+=2
    if context.get("static_limitations"): scores["deep_static_analysis"]+=2
    action=max(scores,key=scores.get); return {"action":action,"scores":{k:(None if math.isinf(v) else round(v,4)) for k,v in scores.items()},"approval_required":action=="request_sandbox_approval","policy":"ucb1_guarded_v1"}


def record_action_reward(action: str, reward: float, *, db_path: Optional[str]=None) -> Dict[str,Any]:
    if action not in {"collect_reference","deep_static_analysis","campaign_correlation","model_review","request_sandbox_approval"} or not -1<=float(reward)<=1: raise ValueError("invalid action reward")
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as c:
        c.execute("""INSERT INTO detection_learning_bandit_actions VALUES (?,1,?,?,?) ON CONFLICT(action_name) DO UPDATE SET pulls=pulls+1,reward_sum=reward_sum+excluded.reward_sum,reward_squared_sum=reward_squared_sum+excluded.reward_squared_sum,updated_at=excluded.updated_at""",(action,float(reward),float(reward)**2,soc_store.utc_now())); c.commit()
    return {"action":action,"reward":float(reward),"recorded":True}


def rollback(proposal_id: str, *, db_path: Optional[str]=None) -> Dict[str,Any]:
    now=soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as c:
        p=c.execute("SELECT proposal_id FROM detection_learning_proposals WHERE proposal_id=?",(_clean(proposal_id,40).upper(),)).fetchone()
        if not p: raise ValueError("learning proposal not found")
        c.execute("UPDATE detection_learning_proposals SET status='rolled_back',updated_at=? WHERE proposal_id=?",(now,p["proposal_id"])); c.execute("UPDATE detection_learning_deployments SET status='rolled_back',completed_at=?,updated_at=? WHERE proposal_id=? AND status='running'",(now,now,p["proposal_id"])); c.commit()
    return {"proposal_id":proposal_id,"status":"rolled_back"}


def status(*, db_path: Optional[str]=None) -> Dict[str,Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as c:
        examples=int(c.execute("SELECT COUNT(*) FROM detection_learning_examples").fetchone()[0]); datasets=[dict(r) for r in c.execute("SELECT * FROM detection_learning_datasets ORDER BY created_at DESC LIMIT 10")]; experiments=[dict(r) for r in c.execute("SELECT * FROM detection_learning_experiments ORDER BY created_at DESC LIMIT 20")]; proposals=[dict(r) for r in c.execute("SELECT * FROM detection_learning_proposals ORDER BY updated_at DESC LIMIT 50")]; deployments=[dict(r) for r in c.execute("SELECT * FROM detection_learning_deployments ORDER BY updated_at DESC LIMIT 50")]
        feedback_total = int(c.execute("SELECT COUNT(*) FROM detection_learning_feedback").fetchone()[0])
        feedback_by_outcome = {
            str(row["outcome"]): int(row["count"])
            for row in c.execute("SELECT outcome, COUNT(*) AS count FROM detection_learning_feedback GROUP BY outcome")
        }
        feedback_eligible = int(c.execute("SELECT COUNT(*) FROM detection_learning_feedback WHERE learning_label IS NOT NULL AND label_source IN ({})".format(",".join("?" for _ in TRUSTED_FEEDBACK_SOURCES)), tuple(sorted(TRUSTED_FEEDBACK_SOURCES))).fetchone()[0])
    for x in datasets: x["label_counts"]=_decode(x.pop("label_counts_json"),{}); x["split_counts"]=_decode(x.pop("split_counts_json"),{}); x.pop("source_policy_json",None)
    for x in experiments: x["model"]=_decode(x.pop("model_json"),{}); x["metrics"]=_decode(x.pop("metrics_json"),{}); x["guardrails"]=_decode(x.pop("guardrails_json"),{})
    for x in proposals: x["parameters"]=_decode(x.pop("parameters_json"),{}); x["replay_metrics"]=_decode(x.pop("replay_metrics_json"),{}); x["rollback"]=_decode(x.pop("rollback_json"),{})
    for x in deployments: x["observations"]=_decode(x.pop("observations_json"),{})
    return {"schema_version":SCHEMA_VERSION,"settings":get_settings(db_path=db_path),"summary":{"examples":examples,"datasets":len(datasets),"experiments":len(experiments),"shadow":sum(p["status"]=="shadow" for p in proposals),"canary":sum(p["status"]=="canary" for p in proposals),"active":sum(p["status"]=="active" for p in proposals),"rolled_back":sum(p["status"]=="rolled_back" for p in proposals),"feedback_total":feedback_total,"feedback_eligible":feedback_eligible,"feedback_by_outcome":feedback_by_outcome},"datasets":datasets,"experiments":experiments,"proposals":proposals,"deployments":deployments}


def run_cycle(*, db_path: Optional[str]=None) -> Dict[str,Any]:
    collected=collect_examples(db_path=db_path); experiment=train(db_path=db_path); promotion=None; settings=get_settings(db_path=db_path)
    if experiment["status"] == "shadow_ready" and settings["mode"] == "guarded" and settings["auto_promote_shadow"]:
        promotion=deploy(experiment["proposal_id"],stage="shadow",db_path=db_path)
    return {"collected":collected,"experiment":experiment,"automatic_shadow":promotion,"external_actions":False,"detector_mutation":False}
