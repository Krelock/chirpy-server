-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;


-- name: DeleteChirp :exec
DELETE FROM chirps WHERE id = $1;

-- name: GetChirpByID :one
SELECT * FROM chirps WHERE id = $1;


-- name: UpgradeChirp :exec
UPDATE users
SET is_chirpy_red = true 
WHERE id = $1;