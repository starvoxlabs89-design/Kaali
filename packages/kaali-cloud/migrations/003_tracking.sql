-- Admin flag on users + tracking snippets table for pixels/meta-tags/scripts.
-- Run:  psql $DATABASE_URL -f migrations/003_tracking.sql

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;

-- Bootstrap first admin from env var KAALI_BOOTSTRAP_ADMIN_EMAIL (set once at deploy).
-- The Node server also checks env at startup to promote a specific email.

CREATE TABLE IF NOT EXISTS tracking_snippets (
  id           BIGSERIAL PRIMARY KEY,
  name         TEXT NOT NULL,                                       -- "Facebook Pixel", "GA4", etc.
  provider     TEXT NOT NULL DEFAULT 'custom',                      -- 'meta-pixel' | 'google-analytics' | 'google-ads' | 'linkedin' | 'tiktok' | 'custom'
  position     TEXT NOT NULL DEFAULT 'head'
                 CHECK (position IN ('head', 'body-start', 'body-end')),
  code         TEXT NOT NULL,                                       -- the raw HTML/script/meta to inject
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  targets      TEXT[] NOT NULL DEFAULT ARRAY['/']::TEXT[],          -- paths to inject on ('/' = landing only, '*' = all pages)
  notes        TEXT,
  created_by   BIGINT REFERENCES users(id) ON DELETE SET NULL,
  updated_by   BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS tracking_snippets_position_enabled_idx
  ON tracking_snippets(position, enabled);

-- Audit log — every write on this table is high-trust, worth persisting.
CREATE TABLE IF NOT EXISTS tracking_audit (
  id           BIGSERIAL PRIMARY KEY,
  snippet_id   BIGINT REFERENCES tracking_snippets(id) ON DELETE CASCADE,
  user_id      BIGINT REFERENCES users(id) ON DELETE SET NULL,
  action       TEXT NOT NULL,                                       -- 'create' | 'update' | 'delete' | 'toggle'
  diff         JSONB,
  ip           INET,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS tracking_audit_created_idx ON tracking_audit(created_at DESC);
