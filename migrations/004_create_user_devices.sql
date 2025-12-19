-- Migration: Create user_devices table
-- Description: Tracks user devices for multi-device session management

-- Up Migration
CREATE TABLE IF NOT EXISTS user_devices (
    id UUID PRIMARY KEY,  -- This is the device_id
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,  -- OAuth client used
    device_name VARCHAR(255),  -- User-friendly name (optional)
    user_agent TEXT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,  -- Supports IPv6
    last_used_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    revoked BOOLEAN NOT NULL DEFAULT FALSE,

    -- Foreign key to oauth_clients (soft reference, client_id not id)
    CONSTRAINT fk_user_devices_client
        FOREIGN KEY (client_id)
        REFERENCES oauth_clients(client_id)
        ON DELETE CASCADE
);

-- Index for looking up devices by user
CREATE INDEX IF NOT EXISTS idx_user_devices_user_id ON user_devices (user_id);

-- Index for active devices by user (most common query)
CREATE INDEX IF NOT EXISTS idx_user_devices_user_active ON user_devices (user_id, revoked)
    WHERE revoked = FALSE;

-- Index for last used (for cleanup/admin)
CREATE INDEX IF NOT EXISTS idx_user_devices_last_used ON user_devices (last_used_at DESC);

-- Down Migration (run separately if needed)
-- DROP TABLE IF EXISTS user_devices;
