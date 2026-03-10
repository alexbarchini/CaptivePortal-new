ALTER TABLE auth_events
  ADD COLUMN IF NOT EXISTS lsid VARCHAR(64),
  ADD COLUMN IF NOT EXISTS cpf VARCHAR(14),
  ADD COLUMN IF NOT EXISTS client_mac VARCHAR(32),
  ADD COLUMN IF NOT EXISTS client_ip VARCHAR(64),
  ADD COLUMN IF NOT EXISTS ssid VARCHAR(128),
  ADD COLUMN IF NOT EXISTS ap_ip VARCHAR(64),
  ADD COLUMN IF NOT EXISTS vlan VARCHAR(64),
  ADD COLUMN IF NOT EXISTS user_agent TEXT,
  ADD COLUMN IF NOT EXISTS details_json JSONB;

UPDATE auth_events
SET lsid = COALESCE(lsid, login_session_id),
    details_json = COALESCE(details_json, detail)
WHERE lsid IS NULL OR details_json IS NULL;

CREATE TABLE IF NOT EXISTS security_events (
  id BIGSERIAL PRIMARY KEY,
  event_type VARCHAR(64) NOT NULL,
  severity VARCHAR(16) NOT NULL,
  correlation_type VARCHAR(32) NOT NULL,
  correlation_value VARCHAR(255) NOT NULL,
  description TEXT,
  reason TEXT,
  attempt_count INTEGER,
  window_seconds INTEGER,
  blocked_until TIMESTAMPTZ,
  details_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE login_sessions
  ADD COLUMN IF NOT EXISTS closed_reason VARCHAR(64),
  ADD COLUMN IF NOT EXISTS authorized_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS status VARCHAR(16);

CREATE INDEX IF NOT EXISTS idx_auth_events_cpf_created
  ON auth_events (cpf, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_events_type_created
  ON auth_events (event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_corr_blocked
  ON security_events (correlation_type, correlation_value, blocked_until DESC, created_at DESC);

