package auth

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"tabbysync/internal/store"
)

func TestNewToken(t *testing.T) {
	tok, hash, hint, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, TokenPrefix) || len(tok) != len(TokenPrefix)+43 {
		t.Fatalf("token %q has unexpected shape", tok)
	}
	if !ValidTokenSyntax(tok) {
		t.Fatal("own token rejected")
	}
	if !bytes.Equal(hash, HashToken(tok)) || len(hash) != 32 {
		t.Fatal("hash mismatch")
	}
	if !strings.HasPrefix(tok, strings.TrimSuffix(hint, "…")) || len(hint) >= len(tok) {
		t.Fatalf("hint %q leaks too much or does not match", hint)
	}
	tok2, _, _, _ := NewToken()
	if tok == tok2 {
		t.Fatal("tokens repeat")
	}
}

func TestValidTokenSyntax(t *testing.T) {
	legacy := strings.Repeat("ab12", 32)
	for tok, want := range map[string]bool{
		legacy:                        true,
		"short":                       false,
		strings.Repeat("a", 257):      false,
		strings.Repeat("a", 40) + " ": false,
		strings.Repeat("a", 40) + "'": false,
		strings.Repeat("a", 40) + "é": false,
	} {
		if got := ValidTokenSyntax(tok); got != want {
			t.Errorf("ValidTokenSyntax(%q) = %v", tok, got)
		}
	}
}

func TestParseScopes(t *testing.T) {
	got, err := ParseScopes(" configs:read, configs:read ,user:read")
	if err != nil || len(got) != 2 {
		t.Fatalf("ParseScopes = %v, %v", got, err)
	}
	for _, bad := range []string{"", ",", "admin", "configs:read,root"} {
		if _, err := ParseScopes(bad); err == nil {
			t.Errorf("ParseScopes(%q) accepted", bad)
		}
	}
}

type fakeLookup map[string]store.AuthRow

func (f fakeLookup) DeviceByTokenHash(_ context.Context, h []byte) (store.AuthRow, error) {
	if r, ok := f[string(h)]; ok {
		return r, nil
	}
	return store.AuthRow{}, store.ErrNotFound
}

func TestAuthenticate(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Second), now.Add(time.Hour)
	rows := map[string]store.AuthRow{
		"ok":       {DeviceID: uuid.New(), UserID: 1, Scopes: []string{ScopeConfigsRead}, ExpiresAt: &future},
		"expired":  {DeviceID: uuid.New(), UserID: 1, ExpiresAt: &now},
		"revoked":  {DeviceID: uuid.New(), UserID: 1, RevokedAt: &past},
		"disabled": {DeviceID: uuid.New(), UserID: 1, UserDisabledAt: &past},
	}
	tokens := map[string]string{}
	lookup := fakeLookup{}
	for name, row := range rows {
		tok, hash, _, _ := NewToken()
		tokens[name] = tok
		lookup[string(hash)] = row
	}
	a := &Authenticator{DB: lookup, Now: func() time.Time { return now }}

	actor, err := a.Authenticate(context.Background(), tokens["ok"])
	if err != nil || actor.UserID != 1 || !actor.Has(ScopeConfigsRead) || actor.Has(ScopeConfigsWrite) {
		t.Fatalf("ok: %+v, %v", actor, err)
	}
	unknown, _, _, _ := NewToken()
	for _, tok := range []string{tokens["expired"], tokens["revoked"], tokens["disabled"], unknown, "bad"} {
		if _, err := a.Authenticate(context.Background(), tok); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("token %q: err = %v", Hint(tok), err)
		}
	}
}
