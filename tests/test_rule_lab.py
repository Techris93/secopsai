import pytest

from scripts import rule_lab
from secopsai.package_features import KNOWN_BENIGN_SHAPES


BENIGN_RULE_LAB_SHAPES = (
    ("tinyexec", ("child_process", "env_read", "install_hook", "tiny_package")),
    ("pnpm", ("anti_analysis", "base64_decode", "browser_data", "child_process", "chmod_exec", "credential_files",
               "dynamic_eval", "env_read", "home_dir", "http_send", "install_hook", "long_base64", "py_subprocess", "system_info")),
    ("retry", ("dns_lookup",)),
)


@pytest.mark.parametrize(("package", "features"), BENIGN_RULE_LAB_SHAPES)
def test_rule_lab_does_not_repropose_a_known_benign_shape(monkeypatch, package, features):
    monkeypatch.setattr(rule_lab, "NOISY_FLAG_SHARE", 2.0)
    monkeypatch.setattr(rule_lab, "FP_BUDGET", 2.0)
    monkeypatch.setattr(rule_lab, "MIN_TRAIN_GAIN", 2)
    rows = [
        {"set": "malicious", "ecosystem": "npm", "status": "scanned", "discovered": "2025-01-01",
         "level": "none", "package": f"train-{package}-{index}", "features": list(features)}
        for index in range(3)
    ]
    rows += [
        {"set": "malicious", "ecosystem": "npm", "status": "scanned", "discovered": "2026-02-01",
         "level": "none", "package": f"heldout-{package}", "features": list(features)},
        {"set": "clean", "ecosystem": "npm", "status": "scanned", "package": package,
         "features": list(features)},
    ]

    assert not rule_lab.propose(rows, ecosystem="npm", cutoff="2026-01-01")
    assert tuple(features) in KNOWN_BENIGN_SHAPES


def test_rule_lab_reports_disjoint_heldout_gains_and_package_overlap():
    rows = []
    for index in range(20):
        package = "train-a-0" if index == 0 else f"train-a-{index}"
        rows.append({"set": "malicious", "ecosystem": "npm", "status": "scanned", "discovered": "2025-01-01",
                     "level": "none", "package": package, "features": ["flag_a"]})
        rows.append({"set": "malicious", "ecosystem": "npm", "status": "scanned", "discovered": "2025-01-01",
                     "level": "none", "package": f"train-b-{index}", "features": ["flag_b"]})

    rows.extend([
        {"set": "malicious", "ecosystem": "npm", "status": "scanned", "discovered": "2026-02-01",
         "level": "none", "package": "new-both", "version": "1", "features": ["flag_a", "flag_b"]},
        {"set": "malicious", "ecosystem": "npm", "status": "scanned", "discovered": "2026-02-01",
         "level": "none", "package": "train-a-0", "version": "2", "features": ["flag_a"]},
        {"set": "malicious", "ecosystem": "npm", "status": "scanned", "discovered": "2026-02-01",
         "level": "none", "package": "new-a", "version": "1", "features": ["flag_a"]},
        {"set": "malicious", "ecosystem": "npm", "status": "scanned", "discovered": "2026-02-02",
         "level": "none", "package": "new-a", "version": "2", "features": ["flag_a"]},
        {"set": "malicious", "ecosystem": "npm", "status": "scanned", "discovered": "2026-02-01",
         "level": "none", "package": "new-b", "version": "1", "features": ["flag_b"]},
    ])
    rows.append({"set": "clean", "ecosystem": "npm", "status": "scanned", "package": "popular-clean-a", "features": ["flag_a"]})
    rows.extend({"set": "clean", "ecosystem": "npm", "status": "scanned", "package": f"clean-{index}", "features": []}
                for index in range(199))

    proposals = rule_lab.propose(rows, ecosystem="npm", cutoff="2026-01-01", max_rules=2)
    assert [proposal["flags"] for proposal in proposals] == [["flag_b"], ["flag_a"]]
    assert [proposal["test_gain"] for proposal in proposals] == [2, 3]
    assert [proposal["test_packages"] for proposal in proposals] == [2, 2]
    assert [proposal["test_training_overlap_packages"] for proposal in proposals] == [0, 1]
    assert proposals[1]["clean_hit_packages"] == ["popular-clean-a"]
    assert sum(proposal["test_gain"] for proposal in proposals) == 5

    summary = rule_lab.report(proposals, "2026-01-01")
    assert "incremental" in summary.lower()
    assert "popular-clean-a" in summary
