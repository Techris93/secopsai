import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import findings
import swarm
from detect import run_detection
from evaluate import compute_metrics


class DetectionRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data_dir = REPO_ROOT / "data"
        fixtures_dir = data_dir / "fixtures"
        labeled_path = data_dir / "events.json"
        unlabeled_path = data_dir / "events_unlabeled.json"
        if not labeled_path.exists():
            labeled_path = fixtures_dir / "events.json"
        if not unlabeled_path.exists():
            unlabeled_path = fixtures_dir / "events_unlabeled.json"
        cls.labeled_events = json.loads(labeled_path.read_text(encoding="utf-8"))
        cls.unlabeled_events = json.loads(unlabeled_path.read_text(encoding="utf-8"))

    def test_detection_matches_benchmark_dataset(self):
        results = run_detection(self.unlabeled_events)
        metrics = compute_metrics(results["detected_event_ids"], self.labeled_events)

        # Keep a realistic regression floor for the current benchmark corpus.
        self.assertGreaterEqual(metrics["f1_score"], 0.75)
        self.assertGreaterEqual(metrics["precision"], 0.70)
        self.assertGreaterEqual(metrics["recall"], 0.85)
        self.assertLessEqual(metrics["false_negatives"], 250)


class SwarmSafetyTests(unittest.TestCase):
    def test_adopt_branch_refuses_dirty_worktree(self):
        show_result = subprocess.CompletedProcess(
            args=["git", "show"],
            returncode=0,
            stdout="print('candidate')\n",
            stderr="",
        )

        with mock.patch.object(swarm, "branch_exists", return_value=True), \
             mock.patch.object(swarm, "get_branch_score", return_value=0.99), \
             mock.patch.object(swarm, "has_uncommitted_changes", return_value=True), \
             mock.patch.object(swarm, "git", return_value=show_result) as git_mock:
            swarm.adopt_branch("experiment/agent-1", confirm=True)

        git_mock.assert_called_once_with(["show", "experiment/agent-1:detect.py"], check=False)

    def test_adopt_branch_restores_detect_on_commit_failure(self):
        show_result = subprocess.CompletedProcess(
            args=["git", "show"],
            returncode=0,
            stdout="print('candidate')\n",
            stderr="",
        )
        ok_result = subprocess.CompletedProcess(args=["git"], returncode=0, stdout="", stderr="")

        git_calls = []

        def fake_git(args, check=True):
            git_calls.append((args, check))
            if args == ["show", "experiment/agent-1:detect.py"]:
                return show_result
            if args == ["checkout", "main"]:
                return ok_result
            if args == ["add", "detect.py"]:
                return ok_result
            if args[:2] == ["commit", "-m"]:
                raise subprocess.CalledProcessError(
                    1,
                    ["git", *args],
                    stderr="commit rejected",
                )
            if args == ["restore", "--source=HEAD", "--", "detect.py"]:
                return ok_result
            if args == ["checkout", "feature/current"]:
                return ok_result
            raise AssertionError(f"unexpected git call: {args}")

        with mock.patch.object(swarm, "branch_exists", return_value=True), \
             mock.patch.object(swarm, "get_branch_score", return_value=0.99), \
             mock.patch.object(swarm, "has_uncommitted_changes", return_value=False), \
             mock.patch.object(swarm, "get_current_branch", return_value="feature/current"), \
             mock.patch.object(swarm, "git", side_effect=fake_git), \
             mock.patch("builtins.open", mock.mock_open()):
            swarm.adopt_branch("experiment/agent-1", confirm=True)

        self.assertIn((["restore", "--source=HEAD", "--", "detect.py"], False), git_calls)
        self.assertEqual(git_calls[-1], (["checkout", "feature/current"], False))


class FindingsPublisherTests(unittest.TestCase):
    def test_detect_github_repo_handles_ssh_remote(self):
        remote_result = subprocess.CompletedProcess(
            args=["git", "remote", "get-url", "origin"],
            returncode=0,
            stdout="git@github.com:example/secopsai.git\n",
            stderr="",
        )

        with mock.patch.object(findings.subprocess, "run", return_value=remote_result):
            self.assertEqual(findings.detect_github_repo(), "example/secopsai")

    def test_publish_to_github_issue_uses_gh_cli_without_overriding_env(self):
        issue_result = subprocess.CompletedProcess(
            args=["gh", "issue", "create"],
            returncode=0,
            stdout="https://github.com/example/secopsai/issues/1\n",
            stderr="",
        )
        finding = findings.create_finding(
            agent_id="agent-1",
            branch="experiment/agent-1",
            direction="new-rules",
            f1_score=1.0,
            approach="Added fileless detection",
            changes=["Added RULE-007"],
            insights=["Low-volume beaconing is separable by payload size"],
        )

        with mock.patch.object(findings, "detect_github_repo", return_value="example/secopsai"), \
             mock.patch.object(findings.subprocess, "run", return_value=issue_result) as run_mock:
            published = findings.publish_to_github_issue(finding)

        self.assertTrue(published)
        _, kwargs = run_mock.call_args
        self.assertNotIn("env", kwargs)
        self.assertEqual(run_mock.call_args.args[0][1:3], ["issue", "create"])
        self.assertTrue(str(run_mock.call_args.args[0][0]).endswith("gh"))


if __name__ == "__main__":
    unittest.main()
