package auth

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"

	"tabbysync/internal/store"
)

// Actor is the authenticated caller of a request.
type Actor struct {
	UserID   int64
	DeviceID uuid.UUID
	Scopes   []string
}

func (a Actor) Has(scope string) bool { return slices.Contains(a.Scopes, scope) }

type ctxKey struct{}

func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, ctxKey{}, a)
}

func ActorFrom(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(ctxKey{}).(Actor)
	return a, ok
}

// ErrInvalidToken covers unknown, expired and revoked tokens and disabled
// users alike, so the response does not tell an attacker which one it was.
var ErrInvalidToken = errors.New("auth: invalid token")

type Lookup interface {
	DeviceByTokenHash(ctx context.Context, hash []byte) (store.AuthRow, error)
}

type Authenticator struct {
	DB  Lookup
	Now func() time.Time
}

func (a *Authenticator) Authenticate(ctx context.Context, token string) (Actor, error) {
	if !ValidTokenSyntax(token) {
		return Actor{}, ErrInvalidToken
	}
	row, err := a.DB.DeviceByTokenHash(ctx, HashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return Actor{}, ErrInvalidToken
	}
	if err != nil {
		return Actor{}, err
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	if row.RevokedAt != nil || row.UserDisabledAt != nil || (row.ExpiresAt != nil && !now.Before(*row.ExpiresAt)) {
		return Actor{}, ErrInvalidToken
	}
	return Actor{UserID: row.UserID, DeviceID: row.DeviceID, Scopes: row.Scopes}, nil
}
