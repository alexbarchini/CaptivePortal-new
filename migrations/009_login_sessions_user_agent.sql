ALTER TABLE login_sessions
  ADD COLUMN IF NOT EXISTS user_agent TEXT;
