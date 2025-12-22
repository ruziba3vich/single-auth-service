-- Down Migration: Drop oauth_clients table
DROP TRIGGER IF EXISTS oauth_clients_updated_at ON oauth_clients;
DROP INDEX IF EXISTS idx_oauth_clients_client_id;
DROP TABLE IF EXISTS oauth_clients;
