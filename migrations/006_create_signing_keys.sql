-- Migration: Create signing_keys table
-- Description: RSA key pairs for JWT signing with rotation support

-- Up Migration
CREATE TABLE IF NOT EXISTS signing_keys (
    kid VARCHAR(64) PRIMARY KEY,  -- Key ID (appears in JWT header)
    private_key TEXT NOT NULL,    -- PEM-encoded RSA private key
    public_key TEXT NOT NULL,     -- PEM-encoded RSA public key
    algorithm VARCHAR(10) NOT NULL DEFAULT 'RS256',
    active BOOLEAN NOT NULL DEFAULT FALSE,  -- Only one key should be active
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Index for active key lookup
CREATE INDEX IF NOT EXISTS idx_signing_keys_active ON signing_keys (active)
    WHERE active = TRUE;

-- Index for JWKS endpoint (filtering by expiration done at query time)
CREATE INDEX IF NOT EXISTS idx_signing_keys_expires ON signing_keys (expires_at DESC);

-- Ensure only one active key at a time using a partial unique index
CREATE UNIQUE INDEX IF NOT EXISTS idx_signing_keys_single_active ON signing_keys (active)
    WHERE active = TRUE;

-- Down Migration (run separately if needed)
-- DROP TABLE IF EXISTS signing_keys;
