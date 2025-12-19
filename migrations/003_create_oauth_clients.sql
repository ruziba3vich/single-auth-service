-- Migration: Create oauth_clients table
-- Description: OAuth 2.1 client applications

-- Up Migration
CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    client_secret_hash TEXT,  -- NULL for public clients
    name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL,  -- Array of allowed redirect URIs
    grant_types TEXT[] NOT NULL,    -- Array of allowed grant types
    scopes TEXT[] NOT NULL DEFAULT '{"openid", "profile", "email"}',
    is_confidential BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Ensure client_id uniqueness
    CONSTRAINT oauth_clients_client_id_unique UNIQUE (client_id)
);

-- Index for client_id lookups
CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients (client_id);

-- Trigger to auto-update updated_at
CREATE TRIGGER oauth_clients_updated_at
    BEFORE UPDATE ON oauth_clients
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Down Migration (run separately if needed)
-- DROP TRIGGER IF EXISTS oauth_clients_updated_at ON oauth_clients;
-- DROP TABLE IF EXISTS oauth_clients;
