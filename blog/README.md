# SecOpsAI Security Blog

Static-first security blog for `blog.secopsai.dev`, designed for Cloudflare Pages.

## Local Preview

```bash
cd blog
python3 -m http.server 8787
```

Open `http://127.0.0.1:8787/`.

## Cloudflare Pages

Create a new Pages project from the SecOpsAI repo and use:

- Production branch: `main`
- Root directory: `blog`
- Framework preset: `None`
- Build command: `exit 0`
- Build output directory: `.`

Then add the custom domain:

```text
blog.secopsai.dev
```

## Comments Setup

Comments are static-safe and moderated. The browser posts to `/api/comments`, a Cloudflare Pages Function that stores pending comments in Supabase.

Required variables/secrets:

- `SUPABASE_URL`: Supabase project URL
- `SUPABASE_SERVICE_ROLE_KEY`: secret used only by the Pages Function
- `BLOG_COMMENTS_TABLE`: optional, defaults to `blog_comments`
- `BLOG_COMMENT_IP_SALT`: optional secret salt for one-way IP hashing
- `TURNSTILE_SITE_KEY`: optional public Cloudflare Turnstile site key
- `TURNSTILE_SECRET_KEY`: optional secret Turnstile key; when present, comment POSTs must pass Turnstile verification

Wrangler setup:

```bash
# Wrangler stores these as encrypted Pages secrets. Paste values only into prompts;
# do not echo them into shell history or commit them.
wrangler pages secret put SUPABASE_URL --project-name secopsai-blog
wrangler pages secret put SUPABASE_SERVICE_ROLE_KEY --project-name secopsai-blog
wrangler pages secret put BLOG_COMMENT_IP_SALT --project-name secopsai-blog
wrangler pages secret put BLOG_COMMENTS_TABLE --project-name secopsai-blog
wrangler pages secret put TURNSTILE_SITE_KEY --project-name secopsai-blog
wrangler pages secret put TURNSTILE_SECRET_KEY --project-name secopsai-blog
```

Cloudflare UI setup:

1. Open `Workers & Pages -> secopsai-blog -> Settings -> Variables and Secrets`.
2. Add `SUPABASE_URL` as a variable or encrypted secret.
3. Add encrypted secrets for `SUPABASE_SERVICE_ROLE_KEY` and `BLOG_COMMENT_IP_SALT`.
4. Add `BLOG_COMMENTS_TABLE` only if you do not want the default `blog_comments`.
5. Optional but recommended: add Turnstile keys as encrypted secrets named `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY`.
6. Redeploy the latest Pages deployment.

Suggested Supabase table:

```sql
create table if not exists blog_comments (
  id bigserial primary key,
  slug text not null,
  name text not null,
  email text not null,
  body text not null,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  user_agent text,
  ip_hash_hint text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists blog_comments_slug_status_idx
  on blog_comments (slug, status, created_at desc);
```

Moderation workflow:

1. Review rows where `status = 'pending'`.
2. Remove secrets, payloads, spam, or customer data.
3. Set safe comments to `approved`.
4. Set rejected comments to `rejected`.

The page renders comments with `textContent`, not raw HTML. The Pages Function stores a salted one-way IP hash hint rather than a raw IP address. If `TURNSTILE_SECRET_KEY` is configured, the server verifies Cloudflare Turnstile before writing pending comments. If Turnstile is not configured, comments still work with moderation, honeypot, strict field limits, and payload-size checks.

Health check:

```bash
curl https://blog.secopsai.dev/api/comments?health=1
```

`configured` must be `true` before public comment submission works.

## Publishing Automation

Blog publishing is draft-first. External news and generated finding/advisory posts require explicit publish confirmation.

```bash
# Create drafts.
secopsai blog draft-finding <FINDING_ID>
secopsai blog draft-advisory --campaign mini-shai-hulud
secopsai blog draft-news --source https://example.com/security-feed.xml

# Fetch curated world-security news and create review-only drafts.
secopsai blog news-sources list
secopsai blog news-fetch --limit 20
secopsai blog news-draft --limit 5
secopsai blog news-run --limit 5
scripts/blog_newsroom.sh 5

# Automation-friendly daily draft generation from local advisories.
secopsai blog draft-daily --limit 5

# Publish only after review.
secopsai blog publish blog/drafts/<slug>.json --publish
secopsai blog news-review list
secopsai blog news-review show <draft-slug-or-path>
secopsai blog news-review approve <draft-slug-or-path> --note "Reviewed sources"
secopsai blog news-publish-approved --rebuild

# Attach an operator-approved screenshot or image to a draft.
secopsai blog attach-media <draft-slug-or-path> \
  --file /path/to/redacted-alert.png \
  --alt "Redacted SecOpsAI alert showing affected package evidence" \
  --caption "Operator-approved SecOpsAI alert screenshot"

# Rebuild index, RSS, and JSON feeds from published post metadata.
secopsai blog rebuild-feeds
```

Feed UX:

- `feed.xml` is the RSS feed for feed readers, email/news apps, Slack RSS, and
  older aggregation tools.
- `feed.json` is the JSON Feed for scripts, apps, and automation tools that
  prefer structured JSON.
- Both feeds expose the same approved public posts. Raw XML/JSON in a browser is
  expected, so the homepage and `/json-feed` explain what the links are for.

Safety gates:

- Drafts are JSON files under `blog/drafts/`.
- `publish` does nothing public unless `--publish` is present.
- Sensitive token-like values are redacted before rendering.
- External news drafts store source URLs and require human review; they are not autopublished.
- Curated source metadata lives in `blog/data/news-sources.json`; fetched cache entries and generated drafts are operational artifacts unless intentionally reviewed and published.
- News fetch balances across enabled sources and prefers direct government/vendor/project sources before commentary sources, so Socket cannot fill the whole queue by itself.
- To originate SecOpsAI-owned posts, draft from local advisories or SOC findings with `secopsai blog draft-advisory` and `secopsai blog draft-finding`.
- `scripts/blog_newsroom.sh` is the one-command daily helper: it fetches news, creates review-only drafts, and prints the review queue.
- Public posts may use approved local images from `blog/assets/posts/<slug>/...`; external feed images are treated as draft-only candidates unless an operator explicitly approves and imports them.
- Do not attach screenshots containing tokens, customer data, private hostnames, private tickets, or raw exploit payloads. Redact first, then attach with descriptive alt text.
- If no approved hero image exists, `secopsai blog rebuild-feeds` creates deterministic SecOpsAI social-card SVGs under `blog/assets/social/` and uses them for Open Graph and X/Twitter preview metadata.

## Publishing From Advisories

Generate a draft from an advisory campaign:

```bash
secopsai blog draft-advisory --campaign mini-shai-hulud
```

Review the draft, then publish it with `secopsai blog publish blog/drafts/<slug>.json --publish`.
