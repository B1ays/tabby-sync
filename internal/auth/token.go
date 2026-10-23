// Package auth implements per-device bearer tokens.
//
// A token is "tbs_" followed by 32 random bytes in base64url. Only its
// SHA-256 is stored. A slow password hash is unnecessary: the token has 256
// bits of entropy, so the hash cannot be brute-forced, and a fast hash keeps
// the lookup a single indexed query.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
)

const (
	TokenPrefix = "tbs_"
	tokenBytes  = 32
	hintLen     = len(TokenPrefix) + 6
	maxTokenLen = 256
)

// Scopes a device token can carry.
const (
	ScopeConfigsRead  = "configs:read"
	ScopeConfigsWrite = "configs:write"
	ScopeUserRead     = "user:read"
	ScopeUserWrite    = "user:write"
)

var AllScopes = []string{ScopeConfigsRead, ScopeConfigsWrite, ScopeUserRead, ScopeUserWrite}

// DefaultScopes is what the desktop client needs.
var DefaultScopes = []string{ScopeConfigsRead, ScopeConfigsWrite, ScopeUserRead}

// NewToken returns a fresh token, its hash for storage and a short hint.
func NewToken() (token string, hash []byte, hint string, err error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, "", err
	}
	token = TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), Hint(token), nil
}

func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// Hint is the part of a token that may be shown in listings and logs.
func Hint(token string) string {
	if len(token) <= hintLen {
		return token[:min(len(token), 4)] + "…"
	}
	return token[:hintLen] + "…"
}

// ValidTokenSyntax rejects obviously malformed values before they reach the
// database. It accepts both our tokens and imported legacy Tabby Web tokens
// (128 hex characters).
func ValidTokenSyntax(t string) bool {
	if len(t) < 32 || len(t) > maxTokenLen {
		return false
	}
	for i := 0; i < len(t); i++ {
		if !isTokenChar(t[i]) {
			return false
		}
	}
	return true
}

// isTokenChar reports whether c is in the base64url alphabet.
func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		return true
	}
	return false
}

// ParseScopes validates a comma-separated scope list.
func ParseScopes(s string) ([]string, error) {
	var out []string
	for _, sc := range strings.Split(s, ",") {
		sc = strings.TrimSpace(sc)
		if sc == "" {
			continue
		}
		if !slices.Contains(AllScopes, sc) {
			return nil, fmt.Errorf("unknown scope %q (known: %s)", sc, strings.Join(AllScopes, ", "))
		}
		if !slices.Contains(out, sc) {
			out = append(out, sc)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one scope is required")
	}
	return out, nil
}
