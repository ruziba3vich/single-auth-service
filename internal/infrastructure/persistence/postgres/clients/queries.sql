-- name: CreateOAuthClient :exec
INSERT INTO oauth_clients (id, client_id, client_secret_hash, name, redirect_uris, grant_types, scopes, is_confidential, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetOAuthClientByID :one
SELECT * FROM oauth_clients WHERE id = $1;

-- name: GetOAuthClientByClientID :one
SELECT * FROM oauth_clients WHERE client_id = $1;

-- name: UpdateOAuthClient :exec
UPDATE oauth_clients
SET client_secret_hash = $2, name = $3, redirect_uris = $4, grant_types = $5, scopes = $6, is_confidential = $7, updated_at = $8
WHERE id = $1;

-- name: DeleteOAuthClient :exec
DELETE FROM oauth_clients WHERE id = $1;

-- name: ListOAuthClients :many
SELECT * FROM oauth_clients ORDER BY created_at DESC LIMIT $1 OFFSET $2;
