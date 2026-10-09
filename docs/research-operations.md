# Research Operations: From Intake To Publication

This is the operating guide for running SecOpsAI as a security research
program: continuous registry surveillance, investigating leads, reaching a
defensible verdict, and publishing research that holds up to scrutiny.

Every command on this page was run end to end on 9 October 2026 against an
isolated ledger (a live npm release and a synthetic positive control), and
the results are recorded under [Verification record](#verification-record).

## Platform map

| Surface | URL / location | Runs on | Purpose |
| --- | --- | --- | --- |
| Website | `https://secopsai.dev` | Cloudflare Pages (`www/`) | Product site and installers |
| Documentation | `https://docs.secopsai.dev` | Cloudflare Pages (MkDocs) | This guide |
| Research blog | `https://blog.secopsai.dev` | Cloudflare Pages + Worker, comments in D1 | Published research |
| Mission Control | `https://dashboard.secopsai.dev` | Cloudflare Pages + Worker | Operator console |
| Core Edge API | `https://core.secopsai.dev` | Worker + D1 | Alerts, heartbeats, ontology, coordinator |
| Ledger store | `https://ledger.secopsai.dev` | Worker + R2 | Research ledger checkpoints |
| Research worker | GitHub Actions **Research Worker** | Free scheduled runner | Registry collectors, triage, daily automation |

Every public domain publishes `/.well-known/security.txt` (RFC 9116).

## Daily loop

1. **The worker runs every 30 minutes** (`.github/workflows/research-worker.yml`).
   Each run restores the ledger from R2, runs 20 worker cycles (eight
   registry collectors, npm enrichment and static triage, external advisory
   intake, scoring, daily automation, retention), checkpoints the ledger and
   exits. One run at a time is enforced.
2. **Review alerts** in Mission Control (Research) or with
   `secopsai research alert list`. Severity now reflects corroborated
   behaviour: `critical`/`high` require a behaviour chain such as
   install-time execution with network egress; generic capability strings
   alone stay low.
3. **Open a case** for anything worth a closer look (next section).

Health checks:

```bash
gh run list --workflow research-worker.yml --limit 5
curl -s https://core.secopsai.dev/healthz
curl -s https://ledger.secopsai.dev/healthz
```

## Investigate a package

```bash
secopsai research package --ecosystem npm --package <name> --version <version> \
  --comparison-ecosystem npm --comparison-package <name> --comparison-version <previous> \
  --research-type package_compromise
```

The pipeline resolves registry metadata, verifies checksums, quarantines the
artifact, inspects it statically (nothing is installed or executed), compares
it with the previous release, validates IOCs, and opens a case when the
evidence warrants one. Read these fields in the JSON (`--json`):

| Field | Meaning |
| --- | --- |
| `scan.findings` | Rule hits (single regex hits are medium confidence) |
| `comparison` | Added/removed files, lifecycle-hook changes, indicator deltas |
| `validated_iocs` / `rejected_iocs` | Accepted indicators and why others were rejected (e.g. *expected service endpoint for this package*) |
| `verdict`, `severity`, `confidence` | Deterministic triage, not a publication verdict |
| `case_id`, `evidence_ids` | The case and its `EVD-` evidence IDs for the verdict command |

For a local artifact (for example, one shared by a partner) add
`--artifact path/to/package.tgz --source-reference <url>`.

## Case to publication

Run these in order. Each gate exists to stop a weak claim from being
published; none of them can be skipped by a flag.

```bash
C=RSC-XXXXXXXXXXXX

# 1. Evidence and brief
secopsai research workflow evidence-matrix $C
secopsai research workflow analyst-brief $C

# 2. Verdict (needs at least one EVD- id that belongs to the case)
secopsai research workflow verdict $C --verdict likely --confidence 80 \
  --rationale "What the evidence shows, and what it does not" \
  --evidence-id EVD-... --actor "<your name>"

# 3. Reliability chain
for step in plan run-scaffold verify-transition run-full verify-claims \
            audit-completeness audit-originality queue-specialist; do
  secopsai research reliability $step $C --actor "<your name>"
done

# 4. Specialist + blinded independent review (human path)
secopsai research reliability human-review $C --stage primary \
  --verdict likely --reviewer "<analyst A>" --evidence-id EVD-... \
  --summary "At least 40 characters explaining the primary assessment"
secopsai research reliability human-review $C --stage reviewer \
  --verdict likely --reviewer "<analyst B>" --evidence-id EVD-... \
  --summary "Independent confirmation or disagreement, with reasons"

# 5. Visual QA of the would-be post (headless Chrome/Chromium/Brave/Edge)
secopsai research reliability visual-qa $C --auto

# 6. Publication safety review and editorial approval
secopsai research workflow publication-check $C
secopsai research workflow publication-approve $C --actor "<editor>"

# 7. Disclosure: prepare a draft (only for likely/credible verdicts), deliver
#    it through the approved channel, or record why none is required
secopsai research workflow prepare-disclosure $C --recipient security@vendor.example
secopsai research case update $C --disclosure-status disclosed   # or not_required

# 8. Draft, publish, deploy
secopsai research case update $C --status ready_to_publish --actor "<editor>"
secopsai research case draft-blog $C
secopsai blog publish blog/drafts/<draft>.json --publish
gh workflow run blog-ops.yml -f action=deploy
```

Rules the pipeline enforces:

- The independent reviewer must be a different person from the primary
  analyst; opposite verdicts require adjudication
  (`research reliability adjudicate-review`).
- Disclosure drafts are refused unless the latest verdict is `likely` or
  `credible`, and re-preparing updates the open draft instead of creating a
  duplicate.
- Visual QA fails on horizontal overflow at 1280 px or 390 px, missing image
  alt text, or WCAG AA contrast failures; screenshots are stored as evidence.
- Every factual sentence in the draft is checked against the claim ledger;
  unsupported claims block the draft.

The model-backed specialist path (`research reliability queue-specialist`
with an execute tier) can replace step 4 when the intelligence bridge is
healthy; see [Model bridge](#model-bridge).

## Security news

News posts are commentary on other publishers' work, so they face a strict
gate: they need extracted intelligence (a CVE, CERT/CC VU# or GHSA ID,
package, product, IP, or hash), must not be vendor marketing, and need a
specific SecOpsAI angle rather than the template.

```bash
secopsai blog news-run --limit 8            # fetch + draft
secopsai blog news-review list
secopsai blog news-review show <draft>
secopsai blog news-review edit <draft> ...  # add the specific analysis
secopsai blog news-review approve <draft>
secopsai blog news-publish-approved --rebuild
gh workflow run blog-ops.yml -f action=deploy
```

Prefer original research. A news post should exist only when SecOpsAI adds
something: an affected-package check, a detection, or a mitigation.

## Blog maintenance

```bash
secopsai blog quality-audit        # re-check every published post against the gate
secopsai blog retire <slug> ...    # remove posts (history stays in git)
secopsai blog rebuild-feeds        # index, RSS, JSON feed, sitemap, 404, security.txt
python scripts/verify_blog.py
```

Comments are stored in D1 (`secopsai-blog-comments`) as `pending`. Approve
one with:

```bash
npx wrangler d1 execute secopsai-blog-comments --remote \
  --command "UPDATE blog_comments SET status='approved', moderated_at=datetime('now'), moderated_by='<you>' WHERE id='<id>'"
```

## Mission Control

- Sign in at `https://dashboard.secopsai.dev`. A session is not enough on its
  own: the account must be in `DASHBOARD_OPERATOR_EMAILS` (Pages secret) or
  carry `app_metadata.secopsai_role=operator`.
- Cloudflare-native mode (Access + D1) activates when `CF_ACCESS_TEAM_DOMAIN`
  and `CF_ACCESS_AUD` are set on the Pages project; the `DASHBOARD_DB` D1
  binding is already in place. See the dashboard repository's
  `CLOUDFLARE_PAGES.md`.
- Local mode: `./start-local-dashboard-stack.sh` in
  `secopsai-dashboard/secopsai-dashboard`, then `http://127.0.0.1:45680`.

## Model bridge

```bash
secopsai intelligence bridge doctor
secopsai intelligence bridge configure-models --primary gpt-6.1-sol \
  --fallback xai/grok-4.6 --fallback google-antigravity/gemini-3.5-flash-low \
  --fallback-mode quota_auth
```

`quota_auth` falls back only when the primary model is out of quota or
fails authentication. Choosing fallbacks decides which providers receive
minimized research context; pick providers you are comfortable with.

## Verification record

Run on 9 October 2026 with an isolated ledger; no production data changed.

| Pipeline | Result |
| --- | --- |
| Source-first package research (`@skyline-ts/telegram@0.5.0` vs `0.4.2`) | Scan clean, verdict not_substantiated, no case (benign Telegram client) |
| Positive control (synthetic credential-exfil package, never executed) | Flagged: install hook, credential discovery, download-execute, exfil staging; case opened |
| Evidence matrix / analyst brief | 3/3 claims supported; brief lists all detections |
| Reliability chain | Plan, scaffold, transition, full bundle succeeded; completeness 95; originality passed |
| Human specialist + blinded review | Same-reviewer review refused; independent review recorded without disagreement |
| Visual QA (auto) | Desktop 1280 px and mobile 390 px: no overflow, no missing alt text, no contrast failures |
| Publication check, approval, disclosure gate, draft | Draft created with 100% claim evidence coverage |
| Publish + rebuild | Post, JSON feed, RSS, sitemap updated; tables render |
| Worker cycle (fresh ledger) | 8 collectors complete; 100 npm events, 10 static analyses, 1 calibrated candidate |
| News intake (live feeds) | KEV and CERT/CC notes pass; marketing, newsletters, navigation junk blocked |

Defects found during these runs and fixed: false-positive static rules (DGA,
browser data, persistence, download-execute, IP:port), code tokens reported
as domain IOCs, expected service endpoints treated as IOCs, an overly broad
exfiltration heuristic, unusable evidence IDs, an analyst brief that missed
scan detections, a claim verifier that blocked every source-first case,
specialist review that could never complete under the default tier, visual
QA with no way to render a draft, markdown tables rendered as raw text, a
crash on redacted artifact locators, missing mobile gutters, daily automation
summaries exceeding the database bound, oversized artifacts retried forever,
Atom links pointing at comment feeds, and navigation links ingested as news.
