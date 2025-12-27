-- name: CreateSession :exec
INSERT INTO user_sessions (
    id, user_id, refresh_token_hash, device_id, fcm_token,
    ip_address, session_info, client_id, scope, expires_at,
    revoked, created_at, last_used_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
);

-- name: GetSessionByID :one
SELECT * FROM user_sessions WHERE id = $1;

-- name: GetSessionByTokenHash :one
SELECT * FROM user_sessions WHERE refresh_token_hash = $1;

-- name: GetSessionByDeviceID :one
SELECT * FROM user_sessions WHERE device_id = $1 AND revoked = FALSE;

-- name: GetSessionsByUserID :many
SELECT * FROM user_sessions WHERE user_id = $1 ORDER BY last_used_at DESC;

-- name: GetActiveSessionsByUserID :many
SELECT * FROM user_sessions
WHERE user_id = $1 AND revoked = FALSE AND expires_at > NOW()
ORDER BY last_used_at DESC;

-- name: GetSessionByUserAndDevice :one
SELECT * FROM user_sessions
WHERE user_id = $1 AND device_id = $2 AND revoked = FALSE;

-- name: UpdateSession :exec
UPDATE user_sessions
SET refresh_token_hash = $2, fcm_token = $3, ip_address = $4,
    session_info = $5, scope = $6, expires_at = $7, last_used_at = $8
WHERE id = $1;

-- name: UpdateSessionLastUsed :exec
UPDATE user_sessions
SET last_used_at = NOW(), ip_address = $2
WHERE id = $1;

-- name: UpdateSessionRefreshToken :exec
UPDATE user_sessions
SET refresh_token_hash = $2, expires_at = $3, last_used_at = NOW()
WHERE id = $1;

-- name: RevokeSession :exec
UPDATE user_sessions SET revoked = TRUE WHERE id = $1;

-- name: RevokeSessionByDeviceID :exec
UPDATE user_sessions SET revoked = TRUE WHERE device_id = $1;

-- name: RevokeSessionsByUserID :exec
UPDATE user_sessions SET revoked = TRUE WHERE user_id = $1;

-- name: RevokeSessionsByUserExceptDevice :exec
UPDATE user_sessions
SET revoked = TRUE
WHERE user_id = $1 AND device_id != $2;

-- name: DeleteSession :exec
DELETE FROM user_sessions WHERE id = $1;

-- name: DeleteExpiredSessions :execrows
DELETE FROM user_sessions
WHERE expires_at < NOW() OR revoked = TRUE;

-- name: CountActiveSessionsByUserID :one
SELECT COUNT(*) FROM user_sessions
WHERE user_id = $1 AND revoked = FALSE AND expires_at > NOW();

-- name: UpdateFCMToken :exec
UPDATE user_sessions
SET fcm_token = $2
WHERE refresh_token_hash = $1;

-- name: GetActiveFCMTokensByUserID :many
SELECT fcm_token FROM user_sessions
WHERE user_id = $1 AND revoked = FALSE AND expires_at > NOW() AND fcm_token IS NOT NULL;

-- name: GetOldestActiveSessionByUserID :one
SELECT * FROM user_sessions
WHERE user_id = $1 AND revoked = FALSE
ORDER BY created_at ASC
LIMIT 1;
