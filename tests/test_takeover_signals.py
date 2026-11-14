from datetime import datetime, timedelta, timezone

from secopsai import takeover_signals as ts

TRUSTED = {"name": "GitHub Actions", "trustedPublisher": {"id": "github"}}


def _doc(old, new, *, old_time="2026-11-01T00:00:00.000Z", new_time="2026-11-10T00:00:00.000Z"):
    return {"time": {"created": "x", "1.0.0": old_time, "1.0.1": new_time}, "versions": {"1.0.0": old, "1.0.1": new}}


def test_a_token_published_release_after_trusted_publishing_is_flagged():
    # The 2025-2026 npm worm pattern: a stolen token publishes outside the
    # project's trusted publisher, without provenance, with a new install script.
    old = {"_npmUser": TRUSTED, "dist": {"attestations": {"url": "x"}}, "scripts": {"test": "t"},
           "maintainers": [{"name": "alice"}]}
    new = {"_npmUser": {"name": "alice"}, "dist": {}, "scripts": {"test": "t", "postinstall": "node bundle.js"},
           "maintainers": [{"name": "alice"}]}
    result = ts.npm_signals(_doc(old, new), "1.0.1")
    assert set(result["signals"]) >= {"trusted_publishing_lost", "provenance_lost", "install_script_added"}
    assert result["score"] >= ts.ESCALATE_SCORE and result["previous_version"] == "1.0.0"


def test_an_ordinary_release_is_quiet():
    meta = {"_npmUser": TRUSTED, "dist": {"attestations": {"url": "x"}}, "scripts": {"postinstall": "node x"},
            "maintainers": [{"name": "alice"}], "repository": {"url": "git+https://github.com/a/b.git"}}
    result = ts.npm_signals(_doc(meta, dict(meta)), "1.0.1")
    assert result == {"metadata_available": True, "previous_version": "1.0.0", "signals": [], "score": 0}
    assert ts.npm_signals(_doc(meta, meta), "9.9.9")["metadata_available"] is False


def test_dormancy_and_new_maintainer_alone_do_not_escalate():
    old = {"_npmUser": {"name": "a"}, "maintainers": [{"name": "a"}]}
    new = {"_npmUser": {"name": "a"}, "maintainers": [{"name": "a"}, {"name": "b"}]}
    result = ts.npm_signals(_doc(old, new, old_time="2023-01-01T00:00:00Z"), "1.0.1")
    assert set(result["signals"]) == {"dormant_republish", "maintainer_added"} and result["score"] < ts.ESCALATE_SCORE


def test_pypi_release_without_provenance_soon_after_a_new_owner_is_flagged():
    files = {"1.0": [{"filename": "p-1.0.tar.gz", "upload-time": "2026-10-01T00:00:00Z", "provenance": "https://x"}],
             "1.1": [{"filename": "p-1.1.tar.gz", "upload-time": "2026-11-10T00:00:00Z", "provenance": None}]}
    published = datetime(2026, 11, 10, tzinfo=timezone.utc)
    result = ts.pypi_signals(files, "1.1", role_added_at=published - timedelta(days=2), published_at=published)
    assert set(result["signals"]) == {"provenance_lost", "role_added_recently"} and result["score"] >= ts.ESCALATE_SCORE
    late = ts.pypi_signals(files, "1.1", role_added_at=published - timedelta(days=40), published_at=published)
    assert late["signals"] == ["provenance_lost"] and late["score"] < ts.ESCALATE_SCORE


def test_pypi_files_are_grouped_by_release():
    simple = {"files": [{"filename": "pkg-1.0-py3-none-any.whl"}, {"filename": "pkg-1.0.tar.gz"}, {"filename": "notes.txt"}]}
    assert {key: len(value) for key, value in ts.pypi_files_by_version(simple, ts.pypi_version_of).items()} == {"1.0": 2}
