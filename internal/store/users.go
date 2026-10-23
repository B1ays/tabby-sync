package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID             int64
	Username       string
	Email          *string
	HasIdentity    bool
	ActiveConfigID *int64
	CreatedAt      time.Time
	DisabledAt     *time.Time
}

const userCols = `id, username, email, oidc_subject IS NOT NULL, active_config_id, created_at, disabled_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.HasIdentity, &u.ActiveConfigID, &u.CreatedAt, &u.DisabledAt)
	return u, notFound(err)
}

func (q *Queries) CreateUser(ctx context.Context, username string) (User, error) {
	return q.CreateUserWithEmail(ctx, username, nil)
}

func (q *Queries) CreateUserWithEmail(ctx context.Context, username string, email *string) (User, error) {
	return scanUser(q.db.QueryRow(ctx,
		`INSERT INTO users (username, email) VALUES ($1, $2) RETURNING `+userCols, username, email))
}

func (q *Queries) GetUser(ctx context.Context, id int64) (User, error) {
	return scanUser(q.db.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

// LockUser serialises per-user operations such as the config count check.
func (q *Queries) LockUser(ctx context.Context, id int64) (User, error) {
	return scanUser(q.db.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1 FOR UPDATE`, id))
}

func (q *Queries) GetUserByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(q.db.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE username = $1`, username))
}

func (q *Queries) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := q.db.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (q *Queries) SetUserDisabled(ctx context.Context, id int64, disabled bool) error {
	tag, err := q.db.Exec(ctx,
		`UPDATE users SET disabled_at = CASE WHEN $2 THEN coalesce(disabled_at, now()) END WHERE id = $1`,
		id, disabled)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetActiveConfig sets or clears the active config. The config must be live
// and belong to the user; the composite foreign key enforces ownership too.
func (q *Queries) SetActiveConfig(ctx context.Context, userID int64, configID *int64) error {
	tag, err := q.db.Exec(ctx, `
		UPDATE users SET active_config_id = $2
		WHERE id = $1
		  AND ($2::bigint IS NULL OR EXISTS (
		      SELECT 1 FROM configs c WHERE c.id = $2 AND c.user_id = $1 AND c.deleted_at IS NULL))`,
		userID, configID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (q *Queries) ClearActiveConfig(ctx context.Context, userID, configID int64) error {
	_, err := q.db.Exec(ctx,
		`UPDATE users SET active_config_id = NULL WHERE id = $1 AND active_config_id = $2`, userID, configID)
	return err
}

// AuthRow is what bearer authentication needs about a token.
type AuthRow struct {
	DeviceID       uuid.UUID
	UserID         int64
	Scopes         []string
	ExpiresAt      *time.Time
	RevokedAt      *time.Time
	UserDisabledAt *time.Time
	LastUsedAt     *time.Time
}

func (q *Queries) DeviceByTokenHash(ctx context.Context, hash []byte) (AuthRow, error) {
	var a AuthRow
	err := q.db.QueryRow(ctx, `
		SELECT d.id, d.user_id, d.scopes, d.expires_at, d.revoked_at, u.disabled_at, d.last_used_at
		FROM devices d JOIN users u ON u.id = d.user_id
		WHERE d.token_hash = $1`, hash).
		Scan(&a.DeviceID, &a.UserID, &a.Scopes, &a.ExpiresAt, &a.RevokedAt, &a.UserDisabledAt, &a.LastUsedAt)
	return a, notFound(err)
}

// TouchDevice records use at most once a minute to avoid a write per request.
func (q *Queries) TouchDevice(ctx context.Context, id uuid.UUID, ip string) error {
	_, err := q.db.Exec(ctx, `
		UPDATE devices SET last_used_at = now(), last_ip = $2
		WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, id, ip)
	return err
}

type Device struct {
	ID         uuid.UUID
	UserID     int64
	Name       string
	TokenHint  string
	Scopes     []string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	LastIP     *string
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
}

const deviceCols = `id, user_id, name, token_hint, scopes, created_at, last_used_at, last_ip, expires_at, revoked_at`

func scanDevice(row interface{ Scan(...any) error }) (Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.UserID, &d.Name, &d.TokenHint, &d.Scopes, &d.CreatedAt,
		&d.LastUsedAt, &d.LastIP, &d.ExpiresAt, &d.RevokedAt)
	return d, notFound(err)
}

func (q *Queries) CreateDevice(ctx context.Context, d Device, tokenHash []byte) (Device, error) {
	return scanDevice(q.db.QueryRow(ctx, `
		INSERT INTO devices (id, user_id, name, token_hash, token_hint, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+deviceCols,
		d.ID, d.UserID, d.Name, tokenHash, d.TokenHint, d.Scopes, d.ExpiresAt))
}

func (q *Queries) ListDevices(ctx context.Context, userID int64) ([]Device, error) {
	rows, err := q.db.Query(ctx, `SELECT `+deviceCols+` FROM devices WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (q *Queries) RevokeDevice(ctx context.Context, userID int64, id uuid.UUID) error {
	tag, err := q.db.Exec(ctx,
		`UPDATE devices SET revoked_at = coalesce(revoked_at, now()) WHERE id = $1 AND user_id = $2`, id, userID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (q *Queries) RevokeAllDevices(ctx context.Context, userID int64) (int64, error) {
	tag, err := q.db.Exec(ctx,
		`UPDATE devices SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return tag.RowsAffected(), err
}
