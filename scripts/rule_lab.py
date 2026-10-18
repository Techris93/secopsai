#!/usr/bin/env python3
"""Rule lab: propose behaviour rules from the recall benchmark's misses.

Reads a Recall Benchmark result (per-package behaviour flags, never code) and
searches combinations of flags for rules that catch malware the current
rules miss while staying inside the false-positive budget on popular clean
packages.

Honesty is built in: candidates are chosen only on samples discovered
before ``--cutoff``; the report then gives each rule's gain on samples
discovered on or after the cutoff, which the search never saw.  Proposals
are written as code for a pull request; nothing is applied automatically.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secopsai.package_features import BEHAVIOUR_RULES, KNOWN_BENIGN_SHAPES, SMALL_PACKAGE  # noqa: E402

LEVEL_RANK = {"none": 0, "notice": 1, "warning": 2, "alert": 3}
NOISY_FLAG_SHARE = 0.10  # flags common in clean packages cannot anchor a rule
MAX_CLEAN_HITS_PER_RULE = 1  # per ecosystem
MIN_TRAIN_GAIN = 15
FP_BUDGET = 0.005  # all accepted rules together, per ecosystem
EXCLUDED_FLAGS = {"tiny_package", "install_hook_inline_command"}  # used only through SMALL_PACKAGE


Candidate = Tuple[FrozenSet[str], bool]  # (flags that must all be present, require small package)


def _caught(row: Dict[str, Any]) -> bool:
    return LEVEL_RANK.get(str(row.get("level")), 0) >= 1


def _matches(flags: Set[str], candidate: Candidate) -> bool:
    required, small = candidate
    return required <= flags and (not small or bool(flags & set(SMALL_PACKAGE)))


def _package_names(rows: Iterable[Dict[str, Any]]) -> Set[str]:
    return {str(row.get("package") or "").strip() for row in rows if str(row.get("package") or "").strip()}


def _existing(ecosystem: str) -> Set[Tuple[FrozenSet[str], bool]]:
    """Existing rules as candidates (single-flag groups only), so they are not re-proposed."""
    out = set()
    for _rule, ecosystems, groups, _score in BEHAVIOUR_RULES:
        if ecosystem in ecosystems and all(len(group) == 1 or tuple(group) == SMALL_PACKAGE for group in groups):
            out.add((frozenset(group[0] for group in groups if tuple(group) != SMALL_PACKAGE), any(tuple(group) == SMALL_PACKAGE for group in groups)))
    return out


def propose(rows: List[Dict[str, Any]], *, ecosystem: str, cutoff: str, max_rules: int = 5) -> List[Dict[str, Any]]:
    malicious = [r for r in rows if r["set"] == "malicious" and r["ecosystem"] == ecosystem and r.get("status") == "scanned"]
    clean = [r for r in rows if r["set"] == "clean" and r["ecosystem"] == ecosystem and r.get("status") == "scanned"]
    if not malicious or not clean:
        return []
    train_rows = [r for r in malicious if str(r.get("discovered") or "") < cutoff]
    test_rows = [r for r in malicious if str(r.get("discovered") or "") >= cutoff]
    train_misses = [r for r in train_rows if not _caught(r)]
    test_misses = [r for r in test_rows if not _caught(r)]
    clean_flags = [set(r.get("features") or []) for r in clean]
    share = {flag: sum(flag in flags for flags in clean_flags) / len(clean_flags) for flags in clean_flags for flag in flags}
    pool = sorted({flag for row in train_misses for flag in (row.get("features") or [])
                   if share.get(flag, 0) < NOISY_FLAG_SHARE and flag not in EXCLUDED_FLAGS})
    candidates: List[Candidate] = [(frozenset(combo), small) for size in (1, 2, 3) for combo in itertools.combinations(pool, size) for small in (False, True)]
    existing = _existing(ecosystem)
    chosen: List[Dict[str, Any]] = []
    remaining = list(train_misses)
    remaining_test = list(test_misses)
    training_packages = _package_names(train_rows)
    credited_train_packages: Set[str] = set()
    credited_test_packages: Set[str] = set()
    allowed_clean = int(FP_BUDGET * len(clean_flags))
    flagged_clean: Set[int] = set()
    for _ in range(max_rules):
        best: Optional[Tuple[int, int, Candidate]] = None
        for candidate in candidates:
            if candidate in existing or any(candidate == item["candidate"] for item in chosen):
                continue
            if any(_matches(set(shape), candidate) for shape in KNOWN_BENIGN_SHAPES):
                continue  # would re-create a false positive we already fixed
            hits = {index for index, flags in enumerate(clean_flags) if _matches(flags, candidate)}
            fp = len(hits)
            if fp > MAX_CLEAN_HITS_PER_RULE or len(flagged_clean | hits) > allowed_clean:
                continue
            gain = sum(_matches(set(row.get("features") or []), candidate) for row in remaining)
            # Prefer more catches, then fewer false positives, then simpler rules.
            key = (gain, -fp, -len(candidate[0]) - int(candidate[1]))
            if gain >= MIN_TRAIN_GAIN and (best is None or key > (best[0], -best[1], -len(best[2][0]) - int(best[2][1]))):
                best = (gain, fp, candidate)
        if best is None:
            break
        gain, fp, candidate = best
        flagged_clean |= {index for index, flags in enumerate(clean_flags) if _matches(flags, candidate)}
        train_hits = [row for row in remaining if _matches(set(row.get("features") or []), candidate)]
        test_hits = [row for row in remaining_test if _matches(set(row.get("features") or []), candidate)]
        clean_hit_rows = [row for row in clean if _matches(set(row.get("features") or []), candidate)]
        train_package_names = _package_names(train_hits)
        test_package_names = _package_names(test_hits)
        new_train_packages = train_package_names - credited_train_packages
        new_test_packages = test_package_names - credited_test_packages
        chosen.append({
            "candidate": candidate,
            "flags": sorted(candidate[0]),
            "small_package": candidate[1],
            "ecosystem": ecosystem,
            "train_gain": gain,
            "train_packages": len(new_train_packages),
            "clean_hits": fp,
            "clean_hit_packages": sorted(_package_names(clean_hit_rows)),
            # Held-out figures are incremental in the same order as the
            # train-selected rules, so their sample counts do not double-count.
            "test_gain": len(test_hits),
            "test_packages": len(new_test_packages),
            "test_training_overlap_packages": len(new_test_packages & training_packages),
            "test_samples": len(test_rows),
        })
        credited_train_packages.update(train_package_names)
        credited_test_packages.update(test_package_names)
        train_hit_ids = {id(row) for row in train_hits}
        test_hit_ids = {id(row) for row in test_hits}
        remaining = [row for row in remaining if id(row) not in train_hit_ids]
        remaining_test = [row for row in remaining_test if id(row) not in test_hit_ids]
    return chosen


def as_code(proposals: Iterable[Dict[str, Any]], start: int = 1) -> str:
    lines = []
    for index, item in enumerate(proposals, start):
        name = f"BEH_LAB_{item['ecosystem'].upper().replace('-', '_')}_{index:02d}"
        groups = [f"(\"{flag}\",)" for flag in item["flags"]] + (["SMALL_PACKAGE"] if item["small_package"] else [])
        lines.append(
            f"    # Rule lab: +{item['train_gain']} pre-cutoff misses in {item['train_packages']} packages, "
            f"+{item['test_gain']} incremental held-out misses in {item['test_packages']} packages, "
            f"{item['clean_hits']} popular-clean hit(s)."
        )
        lines.append(f"    (\"{name}\", (\"{item['ecosystem']}\",), ({', '.join(groups)},), 60),")
    return "\n".join(lines)


def report(proposals: List[Dict[str, Any]], cutoff: str) -> str:
    out = ["## Rule lab proposals", "",
           f"Chosen using samples discovered before {cutoff}. Held-out samples from {cutoff} onward are not used for selection.",
           "Held-out gains are incremental across the proposed rules. Package counts deduplicate versions; train-overlap packages are called out.",
           "Clean hits identify packages in this benchmark sample; the clean set is not the whole registry.", ""]
    if not proposals:
        return "\n".join(out + [f"No candidate met the bar (at least {MIN_TRAIN_GAIN} new catches, at most {MAX_CLEAN_HITS_PER_RULE} popular package flagged)."])
    out += ["| Ecosystem | Behaviours (all required) | Throwaway shape | Train gain (samples / packages) | Incremental held-out (samples / packages; train overlap) | Popular clean hits |",
            "| --- | --- | --- | --- | --- | --- |"]
    out += [
        f"| {p['ecosystem']} | {' + '.join(p['flags'])} | {'yes' if p['small_package'] else 'no'} "
        f"| +{p['train_gain']} / {p['train_packages']} "
        f"| +{p['test_gain']} / {p['test_packages']} ({p['test_training_overlap_packages']} overlap) of {p['test_samples']} samples "
        f"| {p['clean_hits']}: {', '.join(p['clean_hit_packages']) or 'none'} |"
        for p in proposals
    ]
    return "\n".join(out)


def apply(code: str, path: Path = ROOT / "secopsai" / "package_features.py") -> None:
    """Insert proposed rules at the end of BEHAVIOUR_RULES (for the review branch)."""
    source = path.read_text(encoding="utf-8")
    marker = ")\n\n\ndef behaviour_findings("
    if marker not in source:
        raise SystemExit("BEHAVIOUR_RULES end marker not found")
    path.write_text(source.replace(marker, code + "\n" + marker, 1), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("benchmark", type=Path, help="recall-benchmark.json from the Recall Benchmark workflow")
    parser.add_argument("--cutoff", default="2026-01-01")
    parser.add_argument("--max-rules", type=int, default=5)
    parser.add_argument("--out", type=Path, default=Path("rule-lab.json"))
    parser.add_argument("--apply", action="store_true", help="Write the proposals into package_features.py")
    args = parser.parse_args()
    rows = json.loads(args.benchmark.read_text(encoding="utf-8"))["rows"]
    proposals = []
    for ecosystem in ("npm", "pypi"):
        proposals += propose(rows, ecosystem=ecosystem, cutoff=args.cutoff, max_rules=args.max_rules)
    text = report(proposals, args.cutoff)
    print(text)
    payload = {"cutoff": args.cutoff, "proposals": [{k: v for k, v in p.items() if k != "candidate"} for p in proposals], "code": as_code(proposals)}
    args.out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.apply and proposals:
        apply(payload["code"])
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        Path(summary).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
