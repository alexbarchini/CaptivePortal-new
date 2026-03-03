ALTER TABLE otp_codes
  ADD COLUMN IF NOT EXISTS ue_ip VARCHAR(45),
  ADD COLUMN IF NOT EXISTS ue_mac VARCHAR(32);

CREATE INDEX IF NOT EXISTS idx_otp_codes_ctx_verified_recent
  ON otp_codes (user_id, ue_ip, ue_mac, verified_at DESC);
