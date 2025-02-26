// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: refresh_token.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const insertRefresh = `-- name: InsertRefresh :exec
INSERT INTO refresh_tokens (
    token,
    created_at,
    updated_at,
    user_id,
    expires_at,
    revoked_at
)VALUES(
 $1,
 NOW(),
 NOW(),
    $2,
NOW() + INTERVAL '60 days',
NULL
)
`

type InsertRefreshParams struct {
	Token  string
	UserID uuid.NullUUID
}

func (q *Queries) InsertRefresh(ctx context.Context, arg InsertRefreshParams) error {
	_, err := q.db.ExecContext(ctx, insertRefresh, arg.Token, arg.UserID)
	return err
}
