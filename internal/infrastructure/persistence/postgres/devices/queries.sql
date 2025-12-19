-- name: CreateUserDevice :exec
INSERT INTO user_devices (id, user_id, client_id, device_name, user_agent, ip_address, last_used_at, created_at, revoked)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetUserDeviceByID :one
SELECT * FROM user_devices WHERE id = $1;

-- name: GetUserDevicesByUserID :many
SELECT * FROM user_devices WHERE user_id = $1 ORDER BY last_used_at DESC;

-- name: GetActiveUserDevicesByUserID :many
SELECT * FROM user_devices WHERE user_id = $1 AND revoked = FALSE ORDER BY last_used_at DESC;

-- name: GetUserDevicesByUserAndClient :many
SELECT * FROM user_devices WHERE user_id = $1 AND client_id = $2 ORDER BY last_used_at DESC;

-- name: UpdateUserDevice :exec
UPDATE user_devices
SET device_name = $2, user_agent = $3, ip_address = $4, last_used_at = $5, revoked = $6
WHERE id = $1;

-- name: RevokeUserDevice :exec
UPDATE user_devices SET revoked = TRUE WHERE id = $1;

-- name: RevokeUserDevicesByUserID :exec
UPDATE user_devices SET revoked = TRUE WHERE user_id = $1;

-- name: RevokeUserDevicesExceptOne :exec
UPDATE user_devices SET revoked = TRUE WHERE user_id = $1 AND id != $2;

-- name: DeleteUserDevice :exec
DELETE FROM user_devices WHERE id = $1;

-- name: CountActiveUserDevicesByUserID :one
SELECT COUNT(*) FROM user_devices WHERE user_id = $1 AND revoked = FALSE;
