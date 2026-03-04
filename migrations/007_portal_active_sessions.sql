CREATE TABLE IF NOT EXISTS portal_active_sessions (
  id UUID PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ue_ip TEXT,
  ue_mac TEXT,
  ssid TEXT,
  authorized_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at TIMESTAMPTZ,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_portal_active_sessions_ue_ip
  ON portal_active_sessions (ue_ip)
  WHERE ended_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_portal_active_sessions_user_id
  ON portal_active_sessions (user_id)
  WHERE ended_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_portal_active_sessions_user_ip_mac
  ON portal_active_sessions (user_id, ue_ip, ue_mac);
