-- Down Migration: Drop user_devices table
DROP INDEX IF EXISTS idx_user_devices_last_used;
DROP INDEX IF EXISTS idx_user_devices_user_active;
DROP INDEX IF EXISTS idx_user_devices_user_id;
DROP TABLE IF EXISTS user_devices;
