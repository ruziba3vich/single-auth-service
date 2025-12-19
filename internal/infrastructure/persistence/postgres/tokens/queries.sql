-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, user_id, client_id, device_id, token_hash, scope, expires_at, revoked, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens WHERE token_hash = $1;

-- name: GetRefreshTokenByID :one
SELECT * FROM refresh_tokens WHERE id = $1;

-- name: GetRefreshTokensByUserID :many
SELECT * FROM refresh_tokens WHERE user_id = $1 ORDER BY created_at DESC;

-- name: GetRefreshTokensByDeviceID :many
SELECT * FROM refresh_tokens WHERE device_id = $1 ORDER BY created_at DESC;

-- name: GetActiveRefreshTokensByUserAndDevice :many
SELECT * FROM refresh_tokens
WHERE user_id = $1 AND device_id = $2 AND revoked = FALSE AND expires_at > $3
ORDER BY created_at DESC;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1;

-- name: RevokeRefreshTokensByDeviceID :exec
UPDATE refresh_tokens SET revoked = TRUE WHERE device_id = $1;

-- name: RevokeRefreshTokensByUserID :exec
UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1;

-- name: RevokeRefreshTokensExceptDevice :exec
UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND device_id != $2;

-- name: DeleteExpiredRefreshTokens :execrows
DELETE FROM refresh_tokens WHERE expires_at < $1;
