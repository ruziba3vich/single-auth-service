-- Migration: Initialize database
-- Description: Creates the auth_service database schema

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Schema version tracking (optional but recommended)
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    description TEXT
);

-- Insert initial version
INSERT INTO schema_migrations (version, description)
VALUES (0, 'Initial schema setup')
ON CONFLICT (version) DO NOTHING;
