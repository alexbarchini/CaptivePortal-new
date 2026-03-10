CREATE INDEX IF NOT EXISTS idx_auth_events_lsid_created
  ON auth_events (lsid, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_events_ip_created
  ON auth_events (client_ip, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_events_mac_created
  ON auth_events (client_mac, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_type_created
  ON security_events (event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_severity_created
  ON security_events (severity, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_blocked_until
  ON security_events (blocked_until DESC);
