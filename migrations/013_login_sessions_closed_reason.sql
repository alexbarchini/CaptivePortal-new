ALTER TABLE login_sessions
  ADD COLUMN IF NOT EXISTS closed_reason VARCHAR(64);
