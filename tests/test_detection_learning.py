import json

import pytest

import soc_store
from secopsai import detection_learning


def _finding(index: int, disposition: str = "true_positive") -> dict:
    return {"finding_id":f"SCM-LEARN-{index}","title":"Package signal","summary":"Evidence-backed package signal.","severity":"high","severity_score":80,"status":"in_review","disposition":disposition,"source":"secopsai-supply-chain","platform":"supply_chain","ecosystem":"npm","package":f"pkg-{index}","new_version":"1.0.0","rule_ids":["RULE-X"],"event_ids":[],"evidence":{"strong_signals":["install_script"]},"first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z"}


def _seed_examples(db: str, count: int = 60):
    soc_store.init_db(db); now=soc_store.utc_now()
    with soc_store.connect(db) as c:
        for i in range(count):
            label="true_positive" if i%2 else "false_positive"; features={k:((i%7)/6 if label=="true_positive" else (i%3)/10) for k in detection_learning.FEATURES}; eid=f"DLE-{i:016X}"; split=detection_learning._split(eid,20)
            c.execute("INSERT INTO detection_learning_examples VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",(eid,"local",f"F-{i}",None,label,"test_verified",100,detection_learning.FEATURE_VERSION,json.dumps(features),split,json.dumps([f"F-{i}"]),now,now))
        c.commit()


def test_model_only_recommendation_is_not_training_truth(tmp_path):
    db=str(tmp_path/"soc.db"); soc_store.persist_findings([_finding(1)],source="secopsai-supply-chain",db_path=db); soc_store.init_db(db); now=soc_store.utc_now()
    with soc_store.connect(db) as c:
        c.execute("""INSERT INTO agent_triage_runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",("ATR-0123456789ABCDEF","finding","SCM-LEARN-1","fp","recommended",None,"model","provider","{}","{}",json.dumps({"model_confidence":99,"validated_evidence_refs":["RULE-X"]}),"recommend_review",1,"{}",None,None,now,now,now)); c.commit()
    result=detection_learning.collect_examples(db_path=db)
    assert result["accepted"]==0 and result["excluded_untrusted"]==1


def test_reproducible_training_shadow_canary_and_false_negative_rollback(tmp_path):
    db=str(tmp_path/"soc.db"); _seed_examples(db); detection_learning.update_settings(mode="guarded",minimum_examples=20,minimum_precision=.5,maximum_false_negative_regression=10,db_path=db)
    result=detection_learning.train(db_path=db)
    assert result["status"]=="shadow_ready" and result["dataset"]["split_counts"]["holdout"]>0
    shadow=detection_learning.deploy(result["proposal_id"],stage="shadow",db_path=db); assert shadow["traffic_percent"]==0
    canary=detection_learning.deploy(result["proposal_id"],stage="canary",db_path=db); assert canary["traffic_percent"]==10
    detection_learning.update_settings(maximum_false_negative_regression=0,db_path=db)
    rolled=detection_learning.record_observation(canary["deployment_id"],outcome="fn",db_path=db)
    assert rolled["status"]=="rolled_back" and rolled["automatic_rollback"] is True


def test_bandit_requires_approval_for_sandbox_and_records_bounded_rewards(tmp_path):
    db=str(tmp_path/"soc.db")
    for action in ("collect_reference","deep_static_analysis","campaign_correlation","model_review"):
        detection_learning.record_action_reward(action,.2,db_path=db)
    recommendation=detection_learning.recommend_action({"reference_available":True,"static_limitations":False},db_path=db)
    assert recommendation["action"]=="request_sandbox_approval" and recommendation["approval_required"] is True
    with pytest.raises(ValueError): detection_learning.record_action_reward("publish",1,db_path=db)
