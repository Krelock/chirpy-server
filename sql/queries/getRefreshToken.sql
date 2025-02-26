-- name: GetRefreshToken :one
SELECT token, user_id, expires_at, revoked_at
FROM refresh_tokens
WHERE token = $1;
