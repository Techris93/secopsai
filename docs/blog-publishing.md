# Security Blog Publishing

SecOpsAI can draft and publish source-backed security blog posts for `blog.secopsai.dev`.

The workflow is intentionally conservative: drafts are generated locally, reviewed by a human, and only become public when `--publish` is passed.

## Draft Sources

```bash
# Draft from a SOC finding.
secopsai blog draft-finding <FINDING_ID>

# Draft from an emergency advisory.
secopsai blog draft-advisory --campaign mini-shai-hulud

# Draft from cross-ecosystem campaign research.
secopsai blog draft-campaign --campaign tests/fixtures/deadcode09284814-campaign.json
secopsai blog draft-campaign --campaign deadcode09284814-infostealer-botnet-campaign

# Draft from an external news URL or RSS feed.
secopsai blog draft-news --source https://example.com/security-feed.xml

# Automation-ready local draft batch. This does not publish.
secopsai blog draft-daily --limit 5
```

Drafts are written to `blog/drafts/*.json`. External-news drafts are review-only and must not be published until an analyst verifies the source, adds SecOpsAI relevance, and confirms no copied article text, secrets, private logs, or raw exploit payloads are present.

## Automated Security-News Ingestion

Curated sources live in `blog/data/news-sources.json`. Each source declares a name, URL or feed URL, type (`rss`, `html`, or `json`), category, trust level, enabled flag, default tags, and a polling-frequency hint.

The default registry now prioritizes direct/primary sources before commentary or aggregator-style sources:

- Government/direct advisories: CISA KEV, CISA News, CERT/CC Vulnerability Notes.
- Vendor/project primary sources: MSRC, GitHub Security Lab, OpenSSF, Google Online Security Blog, Cloudflare Security Blog, Microsoft Security Blog.
- External research/context sources: Socket Blog.

`news-fetch` fetches across all enabled sources before choosing items, so one busy source cannot consume the whole daily draft limit.

Fetch and cache new items:

```bash
secopsai blog news-sources list
secopsai blog news-fetch --limit 20
```

Create review-only drafts from cached news:

```bash
secopsai blog news-draft --limit 5
```

Run both steps together for cron, launchd, GitHub Actions, or a local scheduled task:

```bash
secopsai blog news-run --limit 5
```

For the friendliest local operator flow, run:

```bash
scripts/blog_newsroom.sh 5
```

That fetches news, drafts new items, and prints the review queue plus next-step commands.

External-news posts are not public until reviewed. You can review without editing JSON by hand:

```bash
secopsai blog news-review list
secopsai blog news-review show <draft-slug-or-path>
secopsai blog news-review edit <draft-slug-or-path> --title "..." --summary "..." --severity high --categories "Security News,Threat Intelligence" --references "https://example.com/source" --body-file edited-post.md --note "Edited with source-backed analysis"
secopsai blog news-review approve <draft-slug-or-path> --note "Reviewed sources and SecOpsAI guidance"
secopsai blog news-review reject <draft-slug-or-path> --note "Not relevant or insufficiently sourced"
```

Then run:

```bash
secopsai blog news-publish-approved --rebuild
```

The pipeline stores fetched metadata in `blog/data/news-cache.json`, deduplicates by canonical URL/title hash, and keeps external claims source-linked. Do not commit generated cache entries or generated drafts unless the post has been reviewed and intentionally published.

### Safe Media And Social Previews

Published posts support operator-approved local screenshots and deterministic social preview cards.

Attach only redacted, approved images:

```bash
secopsai blog attach-media <draft-slug-or-path> --file /path/to/redacted-alert.png --alt "Redacted SecOpsAI alert showing package verdict evidence" --caption "Operator-approved alert screenshot"
```

The media helper copies the file into `blog/assets/posts/<slug>/`, records structured metadata, and resets external-news drafts back to review. Do not attach screenshots that contain secrets, customer data, private hostnames, private tickets, raw exploit payloads, or unlicensed third-party images.

External RSS/feed images are stored only as draft metadata candidates. They are not published automatically. If an image is safe and licensed for reuse, download/redact it yourself and attach it with `secopsai blog attach-media`.

Every public post gets Open Graph and X/Twitter Card metadata. If no approved hero image exists, `secopsai blog rebuild-feeds` generates a local SecOpsAI social card under `blog/assets/social/<slug>.svg` and uses it as the preview image.

### Becoming The Originator

Use external news as source context, but originate SecOpsAI-owned posts from your own evidence whenever possible:

```bash
# SecOpsAI-originated advisory post
secopsai blog draft-advisory --campaign <campaign-id>

# SecOpsAI-originated finding post
secopsai blog draft-finding <FINDING_ID>

# SecOpsAI-originated campaign research post
secopsai supply-chain research-campaign --input campaign.json --dry-run --json
secopsai blog draft-campaign --campaign campaign.json
```

For a first-party post, include:

- what SecOpsAI detected locally
- affected packages, systems, or findings
- IOCs and detection logic
- mitigation commands/operators can run
- references to primary sources only where they support the claim

External-source drafts should become your own SecOpsAI analysis before approval. Do not publish article rewrites.

### Suggested Daily Automation

On macOS, a simple `cron` or `launchd` job can run draft creation every morning without publishing anything:

```bash
cd /Users/chrixchange/secopsai
scripts/blog_newsroom.sh 5 >> logs/blog-newsroom.log 2>&1
```

The safe daily rhythm is:

1. Automation runs `scripts/blog_newsroom.sh 5` and creates drafts only.
2. You run `secopsai blog news-review list` and inspect candidates.
3. You approve only source-backed posts you are comfortable publishing.
4. You run `secopsai blog news-publish-approved --rebuild`.
5. You deploy the blog with `npx --yes wrangler@latest pages deploy blog --project-name secopsai-blog --branch main`.

## Dashboard Blog Ops

The hosted `secopsai-dashboard` can manage the same workflow from a protected **Blog Ops** tab. The dashboard browser does not run shell commands. It calls `/api/blog/*` on the dashboard Worker, and the Worker dispatches `.github/workflows/blog-ops.yml` in this repo.

The workflow supports:

```text
news-run
news-fetch
news-draft
approve
reject
needs-review
save-draft
publish-approved
rebuild-feeds
deploy
```

Draft persistence design:

- Generated review drafts are stored under `blog/drafts/`.
- `blog/drafts/*.json` remains ignored locally so routine operator runs do not dirty the worktree.
- The GitHub Actions workflow intentionally uses `git add -f blog/drafts/*.json` so reviewed dashboard drafts persist in the repository and can be listed by the dashboard.
- External-news drafts still cannot publish until their `review_status` is `approved` or `reviewed`.
- External-news drafts also need a passing readiness gate. Approved drafts with
  readiness blockers are skipped and reported by `news-publish-approved`.

## External News Readiness

`secopsai blog news-draft` now enriches each external-news draft before review.
The generator is deterministic and does not use model calls. It extracts what it
can from the source title, summary, category, tags, and URL metadata.

Automatically attached fields include:

- Source metadata: source name, canonical URL, source URL, trust level,
  category, fetched time, published time, and references.
- Extracted intelligence: CVEs, URLs, domains, IPs, hashes, package names,
  ecosystems, products, and severity signals.
- Review checklist: claim support, affected assets, IOCs, actions, SecOpsAI
  detection angle, and copied-text check.
- Readiness fields: `readiness_score`, `readiness_status`,
  `readiness_blockers`, and `readiness_warnings`.

Readiness statuses:

- `ready_to_review`: the draft has enough structure for a human reviewer to
  inspect and approve.
- `needs_edits`: useful draft, but it needs analyst improvements before
  approval.
- `blocked`: do not publish. Fix blockers first.

Common blockers:

- Summary still matches the title.
- No source URL or references.
- Placeholder text remains.
- Body is too thin.
- Recommended actions are generic.
- No SecOpsAI detection or mitigation angle.

Good external-news drafts should include:

- A real source-backed summary in SecOpsAI's own words.
- Specific affected products, packages, CVEs, or an explicit note that none were
  found deterministically.
- Specific recommended actions based on the source type.
- SecOpsAI detection or mitigation context.
- References to the original source.

Bad placeholder drafts look like:

- Repeated title as summary.
- "Review the source" as the main action.
- "Add SecOpsAI detections here" still present.
- Empty IOCs and affected assets with no explanation.

Daily Blog Ops flow:

1. Click **Run fetch + draft**.
2. Open each draft preview.
3. Check readiness score, blockers, extracted CVEs/IOCs/packages/products, and
   source metadata.
4. Edit weak drafts in the repo or reject them.
5. Approve only drafts with no blockers and useful SecOpsAI context.
6. Click **Publish approved**.
7. Click **Deploy blog** after the publish workflow succeeds.

Required dashboard secrets:

- `BLOG_OPS_GITHUB_TOKEN`: fine-grained GitHub token for `Techris93/secopsai` with Actions read/write and Contents read/write.
- `BLOG_OPS_ADMIN_TOKEN`: operator secret pasted into the dashboard for write actions.

Optional dashboard variables:

- `BLOG_OPS_OWNER=Techris93`
- `BLOG_OPS_REPO=secopsai`
- `BLOG_OPS_WORKFLOW=blog-ops.yml`
- `BLOG_OPS_REF=main`

## Publish

```bash
secopsai blog publish blog/drafts/<slug>.json --publish
secopsai blog rebuild-feeds
```

Publishing writes:

- `blog/posts/<slug>.html`
- `blog/posts/<slug>.json`
- `blog/index.html`
- `blog/feed.xml`
- `blog/feed.json`

## RSS and JSON Feed

The blog publishes two subscription feeds:

- RSS: `https://blog.secopsai.dev/feed.xml`
- JSON Feed: `https://blog.secopsai.dev/feed.json`

Both feeds contain the same approved public posts. They exist for different
clients, not because the blog has two separate content streams.

Use RSS when a normal feed reader, email/news app, Slack RSS integration,
Zapier-style workflow, or older aggregator asks for a feed URL. Use JSON Feed
when an app, script, or automation prefers structured JSON. Seeing raw XML or
JSON in a browser is normal for these machine-readable endpoints, but the
homepage and `/json-feed` page explain the difference for human visitors.

Feed rules:

- Drafts, rejected posts, blocked external-news drafts, review checklists, local
  file paths, and secrets must never appear in feeds.
- RSS items should include title, link, guid, publication date, and a useful
  description.
- JSON Feed items should include absolute URLs, summaries, tags/categories,
  author metadata, dates, severity, reading time, and image/social-card metadata
  when available.

## Comments

Comments are handled by a Cloudflare Pages Function and Supabase. Required Cloudflare Pages values for project `secopsai-blog`:

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- Optional `BLOG_COMMENTS_TABLE`, default `blog_comments`
- Optional `BLOG_COMMENT_IP_SALT`
- Optional `TURNSTILE_SITE_KEY`
- Optional `TURNSTILE_SECRET_KEY`

The comments API stores new comments as `pending`, returns only `approved` comments, hashes IP hints, and renders text safely in the browser. When `TURNSTILE_SECRET_KEY` is configured, comment POSTs must pass Cloudflare Turnstile verification before they are written to Supabase.

Health check:

```bash
secopsai blog comments-status
curl https://blog.secopsai.dev/api/comments?health=1
```

## Moderation

Use Supabase SQL or table editor:

```sql
select id, slug, name, body, created_at
from blog_comments
where status = 'pending'
order by created_at desc;

update blog_comments
set status = 'approved', updated_at = now()
where id = 123;

update blog_comments
set status = 'rejected', updated_at = now()
where id = 123;
```

Reject spam, secrets, customer data, exploit payloads, and unsupported claims.

## Cloudflare Deploy

```bash
wrangler pages deploy blog --project-name secopsai-blog --branch main
```

If `blog.secopsai.dev` is pending and DNS cannot be changed by the current token, add this DNS record manually:

- Type: `CNAME`
- Name: `blog`
- Target: `secopsai-blog.pages.dev`
- Proxy: enabled
