package httpapi_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// fakeIdP is a minimal OpenID Connect provider: discovery, JWKS, an
// authorize endpoint that approves immediately and a token endpoint that
// enforces PKCE (S256), client credentials and single-use codes.
type fakeIdP struct {
	t      *testing.T
	srv    *httptest.Server
	signer jose.Signer
	jwks   jose.JSONWebKeySet

	mu    sync.Mutex
	codes map[string]grant
	// Identity returned for the next login, and knobs to break the token.
	Sub, Email  string
	Verified    any
	AuthTime    time.Time
	BadNonce    bool
	BadAudience bool
	Expired     bool
	WrongKey    bool
	wrongSigner jose.Signer
}

type grant struct {
	challenge, nonce, redirect string
	claims                     map[string]any
}

const (
	idpClientID     = "tabby-sync-test"
	idpClientSecret = "test-secret"
)

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	mk := func(k *rsa.PrivateKey) jose.Signer {
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: k, KeyID: "k1"}},
			(&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	f := &fakeIdP{
		t: t, signer: mk(key), wrongSigner: mk(other), codes: map[string]grant{},
		jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}},
		Sub:  "user-1", Email: "alice@example.com", Verified: true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(f.jwks) })
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != idpClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" {
		http.Error(w, "bad authorize request", 400)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	authTime := f.AuthTime
	if authTime.IsZero() {
		authTime = time.Now().Add(-24 * time.Hour) // an old SSO session by default
	}
	claims := map[string]any{
		"sub": f.Sub, "email": f.Email, "email_verified": f.Verified, "auth_time": authTime.Unix(),
	}
	cb := make([]byte, 16)
	_, _ = rand.Read(cb)
	code := base64.RawURLEncoding.EncodeToString(cb)
	f.codes[code] = grant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri"), claims: claims}
	u, _ := url.Parse(q.Get("redirect_uri"))
	v := url.Values{"code": {code}, "state": {q.Get("state")}}
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != idpClientID || secret != idpClientSecret {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	g, found := f.codes[r.PostForm.Get("code")]
	delete(f.codes, r.PostForm.Get("code")) // single use
	f.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || g.redirect != r.PostForm.Get("redirect_uri") ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}

	f.mu.Lock()
	now := time.Now()
	claims := map[string]any{"iss": f.srv.URL, "aud": idpClientID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": g.nonce}
	for k, v := range g.claims {
		claims[k] = v
	}
	if f.BadNonce {
		claims["nonce"] = "something-else"
	}
	if f.BadAudience {
		claims["aud"] = "another-client"
	}
	if f.Expired {
		claims["exp"] = now.Add(-time.Minute).Unix()
	}
	signer := f.signer
	if f.WrongKey {
		signer = f.wrongSigner
	}
	f.mu.Unlock()

	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		f.t.Error(err)
		return
	}
	idt, _ := jws.CompactSerialize()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": idt,
	})
}

func (f *fakeIdP) set(fn func(*fakeIdP)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}
