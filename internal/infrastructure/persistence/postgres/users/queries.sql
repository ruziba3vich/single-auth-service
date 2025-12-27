-- name: CreateUser :exec
INSERT INTO users (
    username, sahiy_user_id, phone, password, avatar, birth_date,
    gender, forbid_login, email, profile_id, register_ip,
    lastlogin_ip, status, created_at, last_login_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
);

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByPhone :one
SELECT * FROM users WHERE phone = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;

-- name: GetUserByLogin :one
SELECT * FROM users
WHERE phone = $1 OR email = $1 OR username = $1;

-- name: UpdateUser :exec
UPDATE users
SET username = $2, sahiy_user_id = $3, phone = $4, password = $5,
    avatar = $6, birth_date = $7, gender = $8, forbid_login = $9,
    email = $10, profile_id = $11, status = $12
WHERE id = $1;

-- name: UpdateLastLogin :exec
UPDATE users
SET last_login_at = NOW(), lastlogin_ip = $2
WHERE id = $1;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: ExistsUserByPhone :one
SELECT EXISTS(SELECT 1 FROM users WHERE phone = $1);

-- name: ExistsUserByEmail :one
SELECT EXISTS(SELECT 1 FROM users WHERE email = $1);

-- name: ExistsUserByUsername :one
SELECT EXISTS(SELECT 1 FROM users WHERE username = $1);
