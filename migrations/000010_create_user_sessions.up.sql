-- Migration: Create user_sessions table
-- Description: Unified session table replacing user_devices and refresh_tokens

CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(64) NOT NULL,
    device_id UUID NOT NULL,
    fcm_token VARCHAR(255) DEFAULT NULL,
    ip_address VARCHAR(45) NOT NULL,  -- Supports IPv6
    session_info JSONB NOT NULL DEFAULT '{}',  -- Stores device name, user agent, browser info, etc.
    client_id VARCHAR(255) NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Ensure token hash uniqueness
    CONSTRAINT user_sessions_token_hash_unique UNIQUE (refresh_token_hash),
    -- Ensure device_id uniqueness per user
    CONSTRAINT user_sessions_device_unique UNIQUE (user_id, device_id)
);

-- Index for token hash lookups (primary query path for token validation)
CREATE INDEX IF NOT EXISTS idx_user_sessions_token_hash ON user_sessions (refresh_token_hash);

-- Index for user sessions (for listing devices and revocation)
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions (user_id);

-- Index for device lookups
CREATE INDEX IF NOT EXISTS idx_user_sessions_device_id ON user_sessions (device_id);

-- Index for active sessions per user (most common query)
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_active ON user_sessions (user_id, revoked)
    WHERE revoked = FALSE;

-- Index for cleanup of expired sessions
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions (expires_at)
    WHERE revoked = FALSE;

-- Index for FCM token lookups
CREATE INDEX IF NOT EXISTS idx_user_sessions_fcm ON user_sessions (fcm_token)
    WHERE fcm_token IS NOT NULL;

-- Index for client-based queries
CREATE INDEX IF NOT EXISTS idx_user_sessions_client ON user_sessions (client_id);

-- Foreign key to oauth_clients
ALTER TABLE user_sessions ADD CONSTRAINT fk_user_sessions_client
    FOREIGN KEY (client_id)
    REFERENCES oauth_clients(client_id)
    ON DELETE CASCADE;
