-- name: CreateUserIdentity :exec
INSERT INTO user_identities (id, user_id, provider, provider_user_id, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetUserIdentitiesByUserID :many
SELECT * FROM user_identities WHERE user_id = $1;

-- name: GetUserIdentityByProvider :one
SELECT * FROM user_identities WHERE provider = $1 AND provider_user_id = $2;

-- name: DeleteUserIdentity :exec
DELETE FROM user_identities WHERE id = $1;

-- name: DeleteUserIdentitiesByUserID :exec
DELETE FROM user_identities WHERE user_id = $1;
