from __future__ import annotations

import pytest

from secopsai.research_operation import fit_projection_budget


def _projection(*, reviews=6, items=8, filler=0):
    return {
        "editions": [
            {"edition_id": "today", "draft": {"body_markdown": "t" * 2000}},
            {"edition_id": "yesterday", "draft": {"body_markdown": "y" * 2000},
             "pending_update": {"new_items": [{"summary": "n" * 1000}], "removed_items": []}},
        ],
        "research_desk": {"items": [{"label": f"item-{index}", "text": "d" * 500} for index in range(items)]},
        "pending_source_reviews": [{"event_id": f"INT-{index}", "excerpt": "r" * 500} for index in range(reviews)],
        "coverage": {"sources": "c" * filler},
    }


def test_nothing_changes_under_budget():
    projection = _projection()
    assert fit_projection_budget(projection, budget=100000) == _projection()


def test_older_drafts_go_first_and_todays_stays():
    fitted = fit_projection_budget(_projection(), budget=7500)
    assert "draft" in fitted["editions"][0]
    assert "draft" not in fitted["editions"][1]
    assert fitted["research_desk"]["projection_trimmed"]["older_drafts"] == 1
    assert fitted["research_desk"]["projection_trimmed"]["todays_draft"] == 0


def test_lower_ranked_entries_go_before_todays_draft_and_are_counted():
    fitted = fit_projection_budget(_projection(), budget=6000)
    assert "draft" in fitted["editions"][0]
    trimmed = fitted["research_desk"]["projection_trimmed"]
    assert trimmed["desk_items"] + trimmed["source_reviews"] > 0
    assert trimmed["todays_draft"] == 0
    assert fitted["research_desk"]["items"][0]["label"] == "item-0"
    assert all(len(item["text"]) == 500 for item in fitted["research_desk"]["items"])


def test_todays_draft_is_the_last_resort():
    fitted = fit_projection_budget(_projection(), budget=4500)
    assert "draft" not in fitted["editions"][0]
    assert fitted["research_desk"]["projection_trimmed"]["todays_draft"] == 1


def test_an_impossible_budget_names_the_section_sizes():
    with pytest.raises(ValueError, match="coverage"):
        fit_projection_budget(_projection(filler=50000), budget=10000)
