-- Down Migration: Drop signing_keys table
DROP INDEX IF EXISTS idx_signing_keys_single_active;
DROP INDEX IF EXISTS idx_signing_keys_expires;
DROP INDEX IF EXISTS idx_signing_keys_active;
DROP TABLE IF EXISTS signing_keys;
