-- D1 schema for blog.secopsai.dev comments (replaces the Supabase table).
-- Apply with:
--   npx wrangler d1 create secopsai-blog-comments
--   npx wrangler d1 execute secopsai-blog-comments --remote --file migrations/blog-comments/0001_blog_comments.sql
-- then bind the database to the secopsai-blog Pages project as COMMENTS_DB.
CREATE TABLE IF NOT EXISTS blog_comments (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'spam')),
  user_agent TEXT NOT NULL DEFAULT '',
  ip_hash_hint TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  moderated_at TEXT,
  moderated_by TEXT
);

CREATE INDEX IF NOT EXISTS blog_comments_slug_status_created
  ON blog_comments (slug, status, created_at DESC);
