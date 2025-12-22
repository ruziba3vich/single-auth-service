-- Migration: Create user_identities table
-- Description: Links users to external identity providers (Google, Apple, etc.)

-- Up Migration
CREATE TABLE IF NOT EXISTS user_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,  -- 'local', 'google', 'apple'
    provider_user_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Ensure unique identity per provider
    CONSTRAINT user_identities_provider_unique UNIQUE (provider, provider_user_id)
);

-- Index for looking up identities by user
CREATE INDEX IF NOT EXISTS idx_user_identities_user_id ON user_identities (user_id);

-- Index for looking up user by provider identity
CREATE INDEX IF NOT EXISTS idx_user_identities_provider ON user_identities (provider, provider_user_id);

-- Down Migration (run separately if needed)
-- DROP TABLE IF EXISTS user_identities;
