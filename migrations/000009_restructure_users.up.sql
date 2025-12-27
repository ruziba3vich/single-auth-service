-- Migration: Restructure users table
-- Description: Replace users table with new schema including phone, username, and additional fields

-- First, drop dependent tables (they will be recreated in subsequent migrations)
DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS user_devices CASCADE;
DROP TABLE IF EXISTS user_identities CASCADE;

-- Drop the old users table
DROP TABLE IF EXISTS users CASCADE;

-- Drop the old trigger function if it exists
DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE;

-- Create the new users table with the new schema
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    sahiy_user_id BIGINT DEFAULT NULL,
    phone VARCHAR(255) NOT NULL UNIQUE,
    password BYTEA NOT NULL,
    avatar VARCHAR(255) DEFAULT NULL,
    birth_date TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    gender SMALLINT DEFAULT NULL,
    forbid_login SMALLINT DEFAULT NULL,
    email VARCHAR(255) UNIQUE DEFAULT NULL,
    profile_id BIGINT DEFAULT NULL,
    register_ip VARCHAR(255) DEFAULT NULL,
    lastlogin_ip VARCHAR(255) DEFAULT NULL,
    status INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for the users table
CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL;

-- Note: Foreign key to user_address will be added when that table exists
-- ALTER TABLE users ADD CONSTRAINT fk_profile FOREIGN KEY (profile_id) REFERENCES user_address(id) ON DELETE SET NULL;
