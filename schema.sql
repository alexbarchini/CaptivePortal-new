CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  cpf VARCHAR(11) UNIQUE NOT NULL,
  phone VARCHAR(20) NOT NULL,
  username_radius VARCHAR(64) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS lgpd_consents (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  accepted_terms BOOLEAN NOT NULL,
  accepted_privacy BOOLEAN NOT NULL,
  accepted_processing BOOLEAN NOT NULL,
  terms_version VARCHAR(50) NOT NULL,
  privacy_version VARCHAR(50) NOT NULL,
  accepted_at TIMESTAMPTZ NOT NULL,
  ip VARCHAR(64),
  user_agent TEXT
);

CREATE TABLE IF NOT EXISTS auth_events (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  cpf VARCHAR(11),
  client_mac VARCHAR(64),
  client_ip VARCHAR(64),
  ap VARCHAR(64),
  ssid VARCHAR(128),
  result VARCHAR(16) NOT NULL,
  reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  raw_params_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_auth_events_created_at ON auth_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_events_cpf ON auth_events(cpf);
