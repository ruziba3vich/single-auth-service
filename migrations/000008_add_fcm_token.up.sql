-- Migration: Add FCM token column to refresh_tokens
-- Description: Stores Firebase Cloud Messaging tokens for push notifications per session

ALTER TABLE refresh_tokens ADD COLUMN fcm_token VARCHAR(255);

-- Index for efficient FCM token lookups by user
CREATE INDEX idx_refresh_tokens_fcm ON refresh_tokens (user_id)
    WHERE fcm_token IS NOT NULL AND revoked = FALSE;
