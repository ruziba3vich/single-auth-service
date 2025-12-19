-- name: CreateSigningKey :exec
INSERT INTO signing_keys (kid, private_key, public_key, algorithm, active, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetSigningKeyByKID :one
SELECT * FROM signing_keys WHERE kid = $1;

-- name: GetActiveSigningKey :one
SELECT * FROM signing_keys WHERE active = TRUE AND expires_at > $1 LIMIT 1;

-- name: GetAllValidSigningKeys :many
SELECT * FROM signing_keys WHERE expires_at > $1 ORDER BY created_at DESC;

-- name: DeactivateAllSigningKeys :exec
UPDATE signing_keys SET active = FALSE;

-- name: ActivateSigningKey :exec
UPDATE signing_keys SET active = TRUE WHERE kid = $1;

-- name: DeleteSigningKey :exec
DELETE FROM signing_keys WHERE kid = $1;

-- name: DeleteExpiredSigningKeys :execrows
DELETE FROM signing_keys WHERE expires_at < $1;
