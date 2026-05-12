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
