# Security Blog Publishing

SecOpsAI can draft and publish source-backed security blog posts for `blog.secopsai.dev`.

The workflow is intentionally conservative: drafts are generated locally, reviewed by a human, and only become public when `--publish` is passed.

## Draft Sources

```bash
# Draft from a SOC finding.
secopsai blog draft-finding <FINDING_ID>

# Draft from an emergency advisory.
secopsai blog draft-advisory --campaign mini-shai-hulud

# Draft from an external news URL or RSS feed.
secopsai blog draft-news --source https://example.com/security-feed.xml

# Automation-ready local draft batch. This does not publish.
secopsai blog draft-daily --limit 5
```

Drafts are written to `blog/drafts/*.json`. External-news drafts are review-only and must not be published until an analyst verifies the source, adds SecOpsAI relevance, and confirms no copied article text, secrets, private logs, or raw exploit payloads are present.

## Automated Security-News Ingestion

Curated sources live in `blog/data/news-sources.json`. Each source declares a name, URL or feed URL, type (`rss`, `html`, or `json`), category, trust level, enabled flag, default tags, and a polling-frequency hint. The default registry includes Socket Blog, CISA News, CISA KEV, GitHub Security Lab, and Microsoft Security Blog.

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
secopsai blog news-review approve <draft-slug-or-path> --note "Reviewed sources and SecOpsAI guidance"
secopsai blog news-review reject <draft-slug-or-path> --note "Not relevant or insufficiently sourced"
```

Then run:

```bash
secopsai blog news-publish-approved --rebuild
```

The pipeline stores fetched metadata in `blog/data/news-cache.json`, deduplicates by canonical URL/title hash, and keeps external claims source-linked. Do not commit generated cache entries or generated drafts unless the post has been reviewed and intentionally published.

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
publish-approved
rebuild-feeds
deploy
```

Draft persistence design:

- Generated review drafts are stored under `blog/drafts/`.
- `blog/drafts/*.json` remains ignored locally so routine operator runs do not dirty the worktree.
- The GitHub Actions workflow intentionally uses `git add -f blog/drafts/*.json` so reviewed dashboard drafts persist in the repository and can be listed by the dashboard.
- External-news drafts still cannot publish until their `review_status` is `approved` or `reviewed`.

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
