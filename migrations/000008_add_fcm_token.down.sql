-- Down Migration: Remove FCM token column from refresh_tokens

DROP INDEX IF EXISTS idx_refresh_tokens_fcm;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS fcm_token;
