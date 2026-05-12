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

The page renders comments with `textContent`, not raw HTML. The Pages Function stores a salted one-way IP hash hint rather than a raw IP address. For stronger rate limiting, add a Cloudflare Turnstile widget or a Workers KV/Durable Object counter before approving public traffic at scale.

## Publishing From Advisories

Generate a draft from an advisory campaign:

```bash
python3 ../scripts/blog_draft_advisory.py --campaign mini-shai-hulud
```

Review the draft, convert it into `posts/<slug>.html`, then update `feed.xml`, `feed.json`, and `index.html`.
