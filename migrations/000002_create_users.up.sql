-- Migration: Create users table
-- Description: Core user identity table

-- Up Migration
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Ensure email uniqueness (case-insensitive)
    CONSTRAINT users_email_unique UNIQUE (email)
);

-- Index for email lookups (most common query)
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- Index for created_at (useful for admin queries)
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users (created_at DESC);

-- Function to auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update updated_at on row modification
CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Down Migration (run separately if needed)
-- DROP TRIGGER IF EXISTS users_updated_at ON users;
-- DROP TABLE IF EXISTS users;
