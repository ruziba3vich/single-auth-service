-- Migration: Create refresh_tokens table
-- Description: Stores refresh tokens bound to users, clients, and devices

-- Up Migration
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    device_id UUID NOT NULL REFERENCES user_devices(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,  -- SHA-256 hash (64 hex chars)
    scope TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Ensure token hash uniqueness
    CONSTRAINT refresh_tokens_hash_unique UNIQUE (token_hash)
);

-- Index for token hash lookups (primary query path)
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens (token_hash);

-- Index for user tokens (for revocation)
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens (user_id);

-- Index for device tokens (for device-specific revocation)
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_device_id ON refresh_tokens (device_id);

-- Index for cleanup of expired tokens
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens (expires_at)
    WHERE revoked = FALSE;

-- Partial index for active tokens only
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_active ON refresh_tokens (user_id, device_id)
    WHERE revoked = FALSE;

-- Down Migration (run separately if needed)
-- DROP TABLE IF EXISTS refresh_tokens;
