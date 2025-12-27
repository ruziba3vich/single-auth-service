-- Down Migration: Drop user_sessions table and restore user_devices and refresh_tokens

DROP TABLE IF EXISTS user_sessions CASCADE;

-- Note: user_devices and refresh_tokens would need to be recreated from their original migrations
-- This down migration only handles dropping the new table
