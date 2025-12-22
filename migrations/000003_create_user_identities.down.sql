-- Down Migration: Drop user_identities table
DROP INDEX IF EXISTS idx_user_identities_provider;
DROP INDEX IF EXISTS idx_user_identities_user_id;
DROP TABLE IF EXISTS user_identities;
