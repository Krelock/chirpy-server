-- name: GetChirps :many
SELECT * FROM chirps WHERE user_id = $1
OR $1 IS NULL
ORDER BY created_at ASC;