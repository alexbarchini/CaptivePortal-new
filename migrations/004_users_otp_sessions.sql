ALTER TABLE users
  ADD COLUMN IF NOT EXISTS nome VARCHAR(120),
  ADD COLUMN IF NOT EXISTS cpf_normalizado VARCHAR(11),
  ADD COLUMN IF NOT EXISTS cpf_formatado VARCHAR(14),
  ADD COLUMN IF NOT EXISTS phone_e164 VARCHAR(16),
  ADD COLUMN IF NOT EXISTS email VARCHAR(255);

UPDATE users
SET cpf_normalizado = COALESCE(cpf_normalizado, regexp_replace(cpf, '\\D', '', 'g')),
    cpf_formatado = COALESCE(cpf_formatado, cpf),
    phone_e164 = COALESCE(phone_e164, CASE WHEN phone LIKE '+%' THEN phone ELSE '+55' || regexp_replace(phone, '\\D', '', 'g') END),
    nome = COALESCE(nome, 'Visitante'),
    email = COALESCE(email, regexp_replace(cpf, '\\D', '', 'g') || '@placeholder.local')
WHERE cpf_normalizado IS NULL OR cpf_formatado IS NULL OR phone_e164 IS NULL OR nome IS NULL OR email IS NULL;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_cpf_normalizado_unique') THEN
    ALTER TABLE users ADD CONSTRAINT users_cpf_normalizado_unique UNIQUE (cpf_normalizado);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS user_verifications (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  phone_verified_at TIMESTAMPTZ,
  email_verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS otp_codes (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  channel VARCHAR(20) NOT NULL,
  destination VARCHAR(32) NOT NULL,
  code_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  verified_at TIMESTAMPTZ,
  blocked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS login_sessions (
  id VARCHAR(64) PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ctx_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS auth_events (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  login_session_id VARCHAR(64),
  event_type VARCHAR(50) NOT NULL,
  status VARCHAR(20) NOT NULL,
  detail JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_otp_codes_user_created_at ON otp_codes (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_sessions_user_created_at ON login_sessions (user_id, created_at DESC);
