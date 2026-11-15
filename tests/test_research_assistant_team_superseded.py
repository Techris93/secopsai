from secopsai.research_assistant_team import mark_superseded


def _team(team_id, case_id, status):
    return {"team_id": team_id, "case_id": case_id, "status": status}


def test_failed_retries_before_a_completed_run_are_superseded():
    teams = [  # newest first
        _team("RTM-NEW-FAIL", "RSC-A", "failed"),      # after the completed run: still shown
        _team("RTM-DONE", "RSC-A", "awaiting_human_review"),
        _team("RTM-OLD-1", "RSC-A", "failed"),
        _team("RTM-OLD-2", "RSC-A", "canceled"),
        _team("RTM-OTHER", "RSC-B", "failed"),         # another case with no completed run
        _team("RTM-RUNNING", "RSC-A", "queued"),       # never hidden
    ]
    flags = {team["team_id"]: team["superseded"] for team in mark_superseded(teams)}
    assert flags == {"RTM-NEW-FAIL": False, "RTM-DONE": False, "RTM-OLD-1": True, "RTM-OLD-2": True,
                     "RTM-OTHER": False, "RTM-RUNNING": False}


def test_review_pack_is_one_page_with_disagreements_first_and_the_commands():
    from secopsai.research_case_sync import REVIEW_PACK_LIMIT, review_pack

    def stage(name, spec, blind, disagree=False):
        return {"stage": name, "material_disagreement": disagree,
                "output": {"verdict_recommendation": spec, "summary": f"{name} summary", "limitations": ["No dynamic analysis", "no dynamic analysis"],
                           "recommended_actions": ["Compare with 0.7.5"]},
                "review": {"verdict_recommendation": blind, "limitations": ["Five of six evidence items omitted"]}}
    team = {"team_id": "RTM-X", "stages": [stage("synthesis", "inconclusive", "inconclusive"),
                                            stage("challenge", "inconclusive", "likely"),
                                            stage("detection", "likely", "likely", disagree=True)]}
    pack = review_pack("RSC-1", team, ["EVD-A", "EVD-B"])
    assert "| challenge | inconclusive | likely | yes |" in pack
    assert "Disagreement in: challenge, detection" in pack
    assert pack.count("No dynamic analysis") == 1, "limitations are deduplicated"
    assert "human-review RSC-1 --stage primary" in pack and "--evidence-id EVD-A --evidence-id EVD-B" in pack
    assert "Model proposals only" in pack and len(pack) <= REVIEW_PACK_LIMIT
