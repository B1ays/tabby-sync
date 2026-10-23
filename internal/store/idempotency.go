package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// StoredResponse is a response recorded for an idempotency key.
type StoredResponse struct {
	Fingerprint []byte
	Status      int
	Headers     map[string]string
	Body        []byte
}

// ClaimIdempotencyKey reserves key for this transaction. It returns
// (nil, nil) when the key is new or its record expired: the caller then
// performs the request and calls CompleteIdempotencyKey before committing.
// Otherwise it returns the stored response.
//
// A concurrent request with the same key blocks on the primary key until
// the first transaction ends, then sees its committed response, so the
// operation runs at most once without an "in progress" state that a crash
// could leave behind.
func (q *Queries) ClaimIdempotencyKey(ctx context.Context, userID int64, key string, fingerprint []byte, ttl time.Duration) (*StoredResponse, error) {
	expires := time.Now().Add(ttl)
	tag, err := q.db.Exec(ctx, `
		INSERT INTO idempotency_keys (user_id, key, fingerprint, status, headers, body, expires_at)
		VALUES ($1, $2, $3, 0, '{}', '', $4)
		ON CONFLICT (user_id, key) DO NOTHING`, userID, key, fingerprint, expires)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 1 {
		return nil, nil
	}
	var r StoredResponse
	var exp time.Time
	err = q.db.QueryRow(ctx, `
		SELECT fingerprint, status, headers, body, expires_at FROM idempotency_keys
		WHERE user_id = $1 AND key = $2 FOR UPDATE`, userID, key).
		Scan(&r.Fingerprint, &r.Status, &r.Headers, &r.Body, &exp)
	if errors.Is(err, pgx.ErrNoRows) {
		// Purged between the two statements; claim it afresh.
		return q.ClaimIdempotencyKey(ctx, userID, key, fingerprint, ttl)
	}
	if err != nil {
		return nil, err
	}
	if time.Now().After(exp) {
		_, err := q.db.Exec(ctx, `
			UPDATE idempotency_keys SET fingerprint = $3, status = 0, headers = '{}', body = '',
			       created_at = now(), expires_at = $4
			WHERE user_id = $1 AND key = $2`, userID, key, fingerprint, expires)
		return nil, err
	}
	return &r, nil
}

func (q *Queries) CompleteIdempotencyKey(ctx context.Context, userID int64, key string, r StoredResponse) error {
	_, err := q.db.Exec(ctx, `
		UPDATE idempotency_keys SET status = $3, headers = $4, body = $5
		WHERE user_id = $1 AND key = $2`, userID, key, r.Status, r.Headers, r.Body)
	return err
}

func (q *Queries) PurgeExpiredIdempotencyKeys(ctx context.Context) (int64, error) {
	tag, err := q.db.Exec(ctx, `DELETE FROM idempotency_keys WHERE expires_at < now()`)
	return tag.RowsAffected(), err
}

// Savepoint runs fn in a nested transaction: if fn fails, only its changes
// are rolled back and the outer transaction can go on.
func (q *Queries) Savepoint(ctx context.Context, fn func(*Queries) error) error {
	tx, ok := q.db.(pgx.Tx)
	if !ok {
		return errors.New("store: Savepoint outside a transaction")
	}
	return pgx.BeginFunc(ctx, tx, func(sp pgx.Tx) error {
		return fn(&Queries{db: sp})
	})
}
