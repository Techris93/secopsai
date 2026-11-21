-- D1 schema for blog.secopsai.dev email subscriptions, in the same database
-- as the comments (bound to the secopsai-blog Pages project as COMMENTS_DB).
-- Apply with:
--   npx wrangler d1 execute secopsai-blog-comments --remote --file migrations/blog-subscribers/0001_blog_subscribers.sql
CREATE TABLE IF NOT EXISTS blog_subscribers (
  email TEXT PRIMARY KEY,                  -- lower-cased
  status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'unsubscribed')),
  confirm_hash TEXT,                       -- SHA-256 of the emailed confirmation token; cleared once used
  confirm_expires_at TEXT,
  confirm_sent_at TEXT,
  unsubscribe_token TEXT NOT NULL UNIQUE,  -- in every email's unsubscribe link
  ip_hash_hint TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  confirmed_at TEXT,
  unsubscribed_at TEXT
);

CREATE INDEX IF NOT EXISTS blog_subscribers_confirm_hash ON blog_subscribers (confirm_hash);
CREATE INDEX IF NOT EXISTS blog_subscribers_status_email ON blog_subscribers (status, email);

-- One row per emailed post. cursor is the last address sent, so a failed
-- send resumes where it stopped instead of mailing anyone twice.
CREATE TABLE IF NOT EXISTS blog_newsletter_sends (
  slug TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  cursor TEXT NOT NULL DEFAULT '',
  recipients INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  finished_at TEXT
);
