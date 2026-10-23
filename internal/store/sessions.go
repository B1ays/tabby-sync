package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type OIDCFlow struct {
	Provider     string
	State        string
	Nonce        string
	PKCEVerifier string
	ReturnTo     string
	Reauth       bool
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

func (q *Queries) CreateOIDCFlow(ctx context.Context, idHash []byte, f OIDCFlow) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO oidc_flows (id_hash, provider, state, nonce, pkce_verifier, return_to, reauth, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		idHash, f.Provider, f.State, f.Nonce, f.PKCEVerifier, f.ReturnTo, f.Reauth, f.ExpiresAt)
	return err
}

// TakeOIDCFlow deletes and returns an unexpired flow, so a flow can be used
// at most once even under concurrent callbacks.
func (q *Queries) TakeOIDCFlow(ctx context.Context, idHash []byte) (OIDCFlow, error) {
	var f OIDCFlow
	err := q.db.QueryRow(ctx, `
		DELETE FROM oidc_flows WHERE id_hash = $1
		RETURNING provider, state, nonce, pkce_verifier, return_to, reauth, created_at, expires_at`, idHash).
		Scan(&f.Provider, &f.State, &f.Nonce, &f.PKCEVerifier, &f.ReturnTo, &f.Reauth, &f.CreatedAt, &f.ExpiresAt)
	if err != nil {
		return f, notFound(err)
	}
	if !time.Now().Before(f.ExpiresAt) {
		return f, ErrNotFound
	}
	return f, nil
}

type Session struct {
	ID              uuid.UUID
	UserID          int64
	Provider        string
	CreatedAt       time.Time
	AuthenticatedAt time.Time
	LastSeenAt      time.Time
	ExpiresAt       time.Time
	IP              *string
	UserAgent       *string
}

const sessionCols = `s.id, s.user_id, s.provider, s.created_at, s.authenticated_at, s.last_seen_at, s.expires_at, s.ip, s.user_agent`

func scanSession(row interface{ Scan(...any) error }) (Session, error) {
	var s Session
	err := row.Scan(&s.ID, &s.UserID, &s.Provider, &s.CreatedAt, &s.AuthenticatedAt, &s.LastSeenAt,
		&s.ExpiresAt, &s.IP, &s.UserAgent)
	return s, notFound(err)
}

func (q *Queries) CreateSession(ctx context.Context, tokenHash []byte, s Session) (Session, error) {
	return scanSession(q.db.QueryRow(ctx, `
		INSERT INTO sessions AS s (id, token_hash, user_id, provider, expires_at, ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+sessionCols,
		s.ID, tokenHash, s.UserID, s.Provider, s.ExpiresAt, s.IP, s.UserAgent))
}

// ActiveSession returns the session for a cookie if it has neither expired
// nor been idle longer than idle, and its user is not disabled.
func (q *Queries) ActiveSession(ctx context.Context, tokenHash []byte, idle time.Duration) (Session, error) {
	return scanSession(q.db.QueryRow(ctx, `
		SELECT `+sessionCols+`
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1
		  AND s.expires_at > now()
		  AND s.last_seen_at > now() - make_interval(secs => $2::double precision)
		  AND u.disabled_at IS NULL`, tokenHash, idle.Seconds()))
}

// TouchSession records activity at most once a minute.
func (q *Queries) TouchSession(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `
		UPDATE sessions SET last_seen_at = now()
		WHERE id = $1 AND last_seen_at < now() - interval '1 minute'`, id)
	return err
}

func (q *Queries) ListSessions(ctx context.Context, userID int64) ([]Session, error) {
	rows, err := q.db.Query(ctx, `
		SELECT `+sessionCols+` FROM sessions s
		WHERE s.user_id = $1 AND s.expires_at > now()
		ORDER BY s.last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (q *Queries) DeleteSession(ctx context.Context, userID int64, id uuid.UUID) error {
	tag, err := q.db.Exec(ctx, `DELETE FROM sessions WHERE id = $1 AND user_id = $2`, id, userID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DeleteOtherSessions signs the user out everywhere except keep.
func (q *Queries) DeleteOtherSessions(ctx context.Context, userID int64, keep uuid.UUID) (int64, error) {
	tag, err := q.db.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND id <> $2`, userID, keep)
	return tag.RowsAffected(), err
}

// PurgeExpiredLogins removes expired sessions and abandoned login flows.
func (q *Queries) PurgeExpiredLogins(ctx context.Context) (int64, error) {
	t1, err := q.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	t2, err := q.db.Exec(ctx, `DELETE FROM oidc_flows WHERE expires_at < now()`)
	return t1.RowsAffected() + t2.RowsAffected(), err
}

// Identities.

func (q *Queries) UserByIdentity(ctx context.Context, issuer, subject string) (User, error) {
	return scanUser(q.db.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2`, issuer, subject))
}

// LinkIdentityByEmail attaches an OIDC identity to a user that an admin
// registered with this email and that has no identity yet.
func (q *Queries) LinkIdentityByEmail(ctx context.Context, email, issuer, subject string) (User, error) {
	return scanUser(q.db.QueryRow(ctx, `
		UPDATE users SET oidc_issuer = $2, oidc_subject = $3
		WHERE lower(email) = lower($1) AND oidc_issuer IS NULL
		RETURNING `+userCols, email, issuer, subject))
}

func (q *Queries) CreateUserWithIdentity(ctx context.Context, username, email, issuer, subject string) (User, error) {
	return scanUser(q.db.QueryRow(ctx, `
		INSERT INTO users (username, email, oidc_issuer, oidc_subject) VALUES ($1, $2, $3, $4)
		RETURNING `+userCols, username, email, issuer, subject))
}

func (q *Queries) SetUserEmail(ctx context.Context, id int64, email *string) error {
	tag, err := q.db.Exec(ctx, `UPDATE users SET email = $2 WHERE id = $1`, id, email)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
