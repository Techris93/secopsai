"""Prefill a person's technical review of a finished assistant team.

The review itself stays human (``research_assurance.review_case`` checks the
reviewer's registered role). This module only does the reading a machine can
do reliably and says, check by check, which of three things is true:

* ``verified``: the ledger proves it (an assessed claim, a recorded
  experiment, a detection test). The proof is listed.
* ``judgement``: only a person can decide it. A note says what to look at.
* ``not_established``: nothing in the ledger supports it yet, so approval is
  impossible until it is.

The dashboard shows verified checks ticked and the others unticked; the
person still records the review. Nothing here records anything.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from secopsai.research_assurance import TECHNICAL_CHECKS, case_fingerprint, claim_assessments
from secopsai.research_operation_store import digest, records

VERIFIED, JUDGEMENT, MISSING = "verified", "judgement", "not_established"
# Core caps every projected string at 4,000 characters, so long text travels
# as parts that the dashboard joins back into the exact original.
PART_LIMIT = 3800
TARGET = "technical_advisory"
# "missing": the evidence matrix records what is not established as a claim
# with that status; it is a gap, not something the draft asserts.
DROPPED_CLAIMS = {"refuted", "rejected", "withdrawn", "retracted", "missing"}
CLAIMS_ACTOR = "automation:review-brief"
ATTRIBUTION = re.compile(r"\b(?:attributed to|operated by|linked to|nation-state|threat actor|actor|attacker|victims?|"
                         r"organizations? affected|compromised systems?|impact(?:ed)? users?)\b", re.I)
EXECUTION_MODES = {"dynamic", "fuzz", "differential", "patch_verification", "detection_test"}


def parts(value: str, limit: int = PART_LIMIT) -> List[str]:
    """Split at line ends so ``"".join(parts(x)) == x`` and no part is too long."""
    out: List[str] = []
    rest = value
    while len(rest) > limit:
        cut = rest.rfind("\n", 0, limit) + 1 or limit
        out.append(rest[:cut])
        rest = rest[cut:]
    return out + ([rest] if rest or not out else [])


def ensure_claims(case: Dict[str, Any], *, db_path: Optional[str] = None) -> Dict[str, Any]:
    """A case reaches review without claims when it skipped the pipeline step
    that builds its evidence matrix. Build it now: the claims are the fixed,
    evidence-derived ones every pipeline case gets (subject, artifact hash,
    static observations, linked sandbox report), never model text. Each still
    needs a person's claim assessment before an approval counts."""
    if case.get("claims"):
        return case
    from secopsai.research_cases import get_case
    from secopsai.research_workflow import build_evidence_matrix

    build_evidence_matrix(case["case_id"], persist=True, actor=CLAIMS_ACTOR, db_path=db_path)
    return get_case(case["case_id"], db_path=db_path)


def _statements(case: Dict[str, Any]) -> List[str]:
    seen, out = set(), []
    for claim in case.get("claims") or []:
        statement = str(claim.get("statement") or "").strip()
        if statement and str(claim.get("status") or "").lower() not in DROPPED_CLAIMS and statement not in seen:
            seen.add(statement)
            out.append(statement[:3000])
    return out[:20]


def _check(key: str, status: str, note: str, proof: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"key": key, "status": status, "note": note[:600], "proof": [str(item)[:200] for item in (proof or [])][:10]}


def draft_text(pack: str, statements: List[str]) -> str:
    """The text under review: the claims word for word (approval requires each
    one to appear in the draft), then the team's review pack."""
    claims = "\n".join(f"- {statement}" for statement in statements) or "- (no material claims recorded)"
    # Stripped: review_case strips the draft before hashing it.
    return f"## Material claims\n\n{claims}\n\n{pack.strip()}".strip()


def technical_checks(case: Dict[str, Any], statements: List[str], draft: str, *, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    case_id = case["case_id"]
    assessed = claim_assessments(case, db_path=db_path)
    experiments = [r for r in records("experiment", case_id=case_id, db_path=db_path) if r["fingerprint"] == case_fingerprint(case)]
    modes = {mode: [r["record_id"] for r in experiments if r["payload"].get("mode") == mode] for mode in {r["payload"].get("mode") for r in experiments}}
    checks = []

    good = [s for s in statements if assessed.get(digest(s), {}).get("current") and assessed[digest(s)].get("assessment") not in {None, "disputed", "unknown"}]
    disputed = [s for s in statements if assessed.get(digest(s), {}).get("assessment") == "disputed"]
    if not statements:
        checks.append(_check("claims", MISSING, "The case has no material claims to review."))
    elif len(good) == len(statements):
        checks.append(_check("claims", VERIFIED, f"All {len(statements)} claims have a current independent assessment.",
                             [assessed[digest(s)].get("assessment", "") + ": " + s[:120] for s in statements]))
    else:
        note = f"{len(statements) - len(good)} of {len(statements)} claims have no current independent assessment"
        note += f" ({len(disputed)} disputed)" if disputed else ""
        checks.append(_check("claims", MISSING, note + ". Record a claim assessment for each before approving."))

    subjects = [s for s in case.get("subjects") or [] if s.get("name")]
    unversioned = [s["name"] for s in subjects if not s.get("version")]
    if not subjects:
        checks.append(_check("affected_versions", MISSING, "No package or artifact is recorded on the case."))
    elif unversioned:
        checks.append(_check("affected_versions", MISSING, "No version recorded for: " + ", ".join(unversioned[:5]) + "."))
    else:
        checks.append(_check("affected_versions", JUDGEMENT, "Confirm these are all the affected versions.",
                             [f"{s['name']}@{s['version']} (registry: {s.get('registry_state') or 'unknown'})" for s in subjects]))

    ran = [rid for mode in EXECUTION_MODES for rid in modes.get(mode, [])]
    sandbox = [e["evidence_id"] for e in case.get("evidence") or [] if e.get("evidence_type") == "sandbox_analysis" and e.get("status", "active") == "active"]
    if ran or sandbox:
        checks.append(_check("reproduction", VERIFIED, "Behaviour was observed by execution.", ran + sandbox))
    else:
        checks.append(_check("reproduction", MISSING, "Nothing has run the package: no sandbox result or execution experiment is recorded."))

    checks.append(_check("materiality", JUDGEMENT, f"Is this worth an advisory? Severity {case.get('severity') or 'unknown'}, "
                         f"impact {case.get('potential_impact') or 'unknown'}, local exposure {case.get('local_exposure') or 'unknown'}."))
    checks.append(_check("alternatives", JUDGEMENT, "Read the independent challenge and any stage marked as a disagreement in the draft."))

    if modes.get("detection_test"):
        checks.append(_check("detections", VERIFIED, "A detection test is recorded.", modes["detection_test"]))
    else:
        checks.append(_check("detections", MISSING, "No detection test is recorded."))

    if modes.get("patch_verification"):
        checks.append(_check("mitigations", VERIFIED, "A patch or mitigation was verified by experiment.", modes["patch_verification"]))
    else:
        checks.append(_check("mitigations", JUDGEMENT, "Check the suggested mitigations are correct; none was verified by experiment."))

    named = sorted({m.group(0).lower() for m in ATTRIBUTION.finditer(draft)})
    if named:
        checks.append(_check("attribution", JUDGEMENT, "The draft mentions " + ", ".join(named[:5]) + ": check each is sourced, not inferred."))
    else:
        checks.append(_check("attribution", VERIFIED, "The draft names no actor, attacker or victim."))

    if "## Still unknown" in draft:
        checks.append(_check("limitations", JUDGEMENT, "Limitations are listed under Still unknown; confirm nothing material is missing."))
    else:
        checks.append(_check("limitations", MISSING, "The draft states no limitations."))
    assert {c["key"] for c in checks} == TECHNICAL_CHECKS
    return checks


def _last_review(case: Dict[str, Any], draft: str, *, db_path: Optional[str]) -> Optional[Dict[str, Any]]:
    for record in records("human_review", case_id=case["case_id"], db_path=db_path):
        value = record["payload"]
        if value.get("role") == "technical_reviewer" and value.get("target", "blog") == TARGET:
            return {"decision": value.get("decision"), "actor": record["actor"], "created_at": record["created_at"],
                    # Current: about this exact case state and this exact draft.
                    "current": record["fingerprint"] == case_fingerprint(case) and value.get("draft_sha256") == digest(draft)}
    return None


def review_assist(case: Dict[str, Any], pack: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    statements = _statements(case)
    draft = draft_text(pack, statements)
    checks = technical_checks(case, statements, draft, db_path=db_path)
    blockers = []
    prior = records("prior_art", case_id=case["case_id"], db_path=db_path)
    if not prior or prior[0]["fingerprint"] != case_fingerprint(case):
        blockers.append("No current prior-art search is recorded.")
    missing = [c for c in checks if c["status"] == MISSING]
    if missing or blockers:
        decision = "changes_required"
        rationale = "Not ready for approval. " + " ".join([c["note"] for c in missing] + blockers)
    else:
        decision = "approved"
        rationale = ("Claims are independently assessed and behaviour was observed by execution. "
                     "I checked materiality, competing explanations, affected versions, mitigations and limitations against the evidence.")
    return {"role": "technical_reviewer", "target": TARGET, "draft_parts": parts(draft), "draft_sha256": digest(draft),
            "claim_statements": statements, "checks": checks, "blockers": blockers,
            "suggested_decision": decision, "suggested_rationale": rationale[:3000],
            "last_review": _last_review(case, draft, db_path=db_path)}

