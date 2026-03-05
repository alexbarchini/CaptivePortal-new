ALTER TABLE login_sessions
  ADD COLUMN IF NOT EXISTS status VARCHAR(16),
  ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ;

UPDATE login_sessions
SET status = CASE WHEN consumed_at IS NULL THEN 'OPEN' ELSE 'CLOSED' END,
    closed_at = CASE WHEN consumed_at IS NOT NULL THEN COALESCE(closed_at, consumed_at) ELSE closed_at END
WHERE status IS NULL;

ALTER TABLE login_sessions
  ALTER COLUMN status SET DEFAULT 'OPEN';

UPDATE login_sessions
SET status = 'OPEN'
WHERE status IS NULL;

ALTER TABLE login_sessions
  ALTER COLUMN status SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS unique_active_session
  ON login_sessions (client_mac)
  WHERE status = 'OPEN';
