package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"tabbysync/internal/auth"
	"tabbysync/internal/config"
	"tabbysync/internal/configs"
	"tabbysync/internal/crypto"
	"tabbysync/internal/httpapi"
	"tabbysync/internal/store"
	"tabbysync/internal/testdb"
)

type env struct {
	t    *testing.T
	db   *store.Store
	url  string
	keys *crypto.Keyring
	svc  *configs.Service
	srv  *httptest.Server
}

func newEnv(t *testing.T, mod func(*config.Config)) *env {
	t.Helper()
	db, url := testdb.Open(t)
	line, _ := crypto.GenerateKeyLine("k1")
	keys, err := crypto.ParseKeyring(strings.NewReader(line), "k1")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		CORSOrigins: []string{"*"},
		Limits:      config.Limits{MaxConfigBytes: 64 << 10, MaxConfigsPerUser: 5},
		Retention:   config.Retention{KeepMin: 1000, MaxAge: time.Hour, HardCap: 10000},
		RateLimit: config.RateLimit{
			IPRate: 10000, IPBurst: 10000, AuthFailPerMinute: 10000, AuthFailBurst: 10000,
			DeviceRate: 10000, DeviceBurst: 10000,
		},
	}
	if mod != nil {
		mod(cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &configs.Service{
		DB: db, Keys: keys, Log: log,
		Limits:    configs.Limits{MaxConfigBytes: cfg.Limits.MaxConfigBytes, MaxConfigsPerUser: cfg.Limits.MaxConfigsPerUser},
		Retention: store.Retention{KeepMin: cfg.Retention.KeepMin, MaxAge: cfg.Retention.MaxAge, HardCap: cfg.Retention.HardCap},
	}
	srv := httptest.NewServer(httpapi.New(cfg, log, db, svc).Handler())
	t.Cleanup(srv.Close)
	return &env{t: t, db: db, url: url, keys: keys, svc: svc, srv: srv}
}

func rawPool(t *testing.T, e *env) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), e.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func (e *env) user(name string) store.User {
	e.t.Helper()
	u, err := e.db.CreateUser(context.Background(), name)
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

func (e *env) token(u store.User, scopes ...string) (string, uuid.UUID) {
	e.t.Helper()
	if len(scopes) == 0 {
		scopes = auth.AllScopes
	}
	tok, hash, hint, err := auth.NewToken()
	if err != nil {
		e.t.Fatal(err)
	}
	d, err := e.db.CreateDevice(context.Background(),
		store.Device{ID: uuid.New(), UserID: u.ID, Name: "test", TokenHint: hint, Scopes: scopes}, hash)
	if err != nil {
		e.t.Fatal(err)
	}
	return tok, d.ID
}

type resp struct {
	*http.Response
	body []byte
}

func (r resp) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

func (e *env) do(method, path, token string, body any, headers ...string) resp {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res, b}
}

func expect(t *testing.T, r resp, status int) {
	t.Helper()
	if r.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", r.Request.Method, r.Request.URL.Path, r.StatusCode, status, r.body)
	}
}

type cfgJSON struct {
	ID                  int64   `json:"id"`
	User                int64   `json:"user"`
	Name                string  `json:"name"`
	Content             string  `json:"content"`
	LastUsedWithVersion *string `json:"last_used_with_version"`
	CreatedAt           string  `json:"created_at"`
	ModifiedAt          string  `json:"modified_at"`
}

// TestDesktopClientFlow replays the requests Tabby's ConfigSyncService makes.
func TestDesktopClientFlow(t *testing.T) {
	e := newEnv(t, nil)
	tok, _ := e.token(e.user("alice"), auth.DefaultScopes...)

	r := e.do("GET", "/api/1/configs", tok, nil)
	expect(t, r, 200)
	if strings.TrimSpace(string(r.body)) != "[]" {
		t.Fatalf("empty list = %s", r.body)
	}

	// createNewConfig sends only the name.
	r = e.do("POST", "/api/1/configs", tok, map[string]any{"name": "Laptop"})
	expect(t, r, 201)
	var c cfgJSON
	r.json(t, &c)
	if c.Name != "Laptop" || c.Content != "{}" || c.ID == 0 || r.Header.Get("ETag") != `"v1"` {
		t.Fatalf("created %+v etag %s", c, r.Header.Get("ETag"))
	}
	if _, err := time.Parse(time.RFC3339Nano, c.ModifiedAt); err != nil {
		t.Fatalf("modified_at %q: %v", c.ModifiedAt, err)
	}
	path := fmt.Sprintf("/api/1/configs/%d", c.ID)

	// upload: GET, then PATCH content + last_used_with_version.
	expect(t, e.do("GET", path, tok, nil), 200)
	content := "version: 3\nprofiles:\n  - name: srv\n    type: ssh\n"
	r = e.do("PATCH", path, tok, map[string]any{"content": content, "last_used_with_version": "1.0.230"})
	expect(t, r, 200)
	var up cfgJSON
	r.json(t, &up)
	if up.Content != content || *up.LastUsedWithVersion != "1.0.230" || up.ModifiedAt <= c.ModifiedAt {
		t.Fatalf("after upload %+v", up)
	}

	// autoSync polls modified_at; an identical upload must not move it.
	r = e.do("PATCH", path, tok, map[string]any{"content": content, "last_used_with_version": "1.0.230"})
	expect(t, r, 200)
	var same cfgJSON
	r.json(t, &same)
	if same.ModifiedAt != up.ModifiedAt {
		t.Fatalf("no-op write moved modified_at %s -> %s", up.ModifiedAt, same.ModifiedAt)
	}

	r = e.do("GET", "/api/1/configs", tok, nil)
	var list []cfgJSON
	r.json(t, &list)
	if len(list) != 1 || list[0].Content != content {
		t.Fatalf("list %+v", list)
	}

	r = e.do("GET", "/api/1/user", tok, nil)
	expect(t, r, 200)
	var u map[string]any
	r.json(t, &u)
	if u["username"] != "alice" || u["config_sync_token"] != nil {
		t.Fatalf("user %v", u)
	}

	r = e.do("DELETE", path, tok, nil)
	expect(t, r, 204)
	if len(r.body) != 0 {
		t.Fatalf("DELETE body %q", r.body)
	}
	expect(t, e.do("GET", path, tok, nil), 404)
	expect(t, e.do("DELETE", path, tok, nil), 404)
}

func TestAuthentication(t *testing.T) {
	e := newEnv(t, nil)
	alice := e.user("alice")
	tok, dev := e.token(alice)
	ctx := context.Background()

	r := e.do("GET", "/api/1/configs", "", nil)
	expect(t, r, 401)
	if !strings.HasPrefix(r.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatal("missing WWW-Authenticate")
	}
	expect(t, e.do("GET", "/api/1/configs?auth_token="+tok, "", nil), 401)
	expect(t, e.do("GET", "/api/1/configs", tok+"x", nil), 401)
	expect(t, e.do("GET", "/api/1/configs", tok, nil, "Authorization", "Basic "+tok), 401)
	expect(t, e.do("GET", "/api/1/configs", tok, nil), 200)

	// Scope enforcement.
	ro, _ := e.token(alice, auth.ScopeConfigsRead)
	expect(t, e.do("GET", "/api/1/configs", ro, nil), 200)
	r = e.do("POST", "/api/1/configs", ro, map[string]any{})
	expect(t, r, 403)
	if !strings.Contains(r.Header.Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatal("missing insufficient_scope")
	}
	expect(t, e.do("GET", "/api/1/user", ro, nil), 403)

	// Revocation takes effect on the next request.
	if err := e.db.RevokeDevice(ctx, alice.ID, dev); err != nil {
		t.Fatal(err)
	}
	expect(t, e.do("GET", "/api/1/configs", tok, nil), 401)

	// Disabling the user invalidates all of their tokens.
	tok2, _ := e.token(alice)
	expect(t, e.do("GET", "/api/1/configs", tok2, nil), 200)
	if err := e.db.SetUserDisabled(ctx, alice.ID, true); err != nil {
		t.Fatal(err)
	}
	expect(t, e.do("GET", "/api/1/configs", tok2, nil), 401)
}

func TestExpiredToken(t *testing.T) {
	e := newEnv(t, nil)
	u := e.user("alice")
	tok, hash, hint, _ := auth.NewToken()
	past := time.Now().Add(-time.Minute)
	if _, err := e.db.CreateDevice(context.Background(), store.Device{
		ID: uuid.New(), UserID: u.ID, Name: "old", TokenHint: hint, Scopes: auth.AllScopes, ExpiresAt: &past,
	}, hash); err != nil {
		t.Fatal(err)
	}
	expect(t, e.do("GET", "/api/1/configs", tok, nil), 401)
}

func TestAuthFailureRateLimit(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.RateLimit.AuthFailPerMinute, c.RateLimit.AuthFailBurst = 1, 3 })
	tok, _ := e.token(e.user("alice"))
	bad, _, _, _ := auth.NewToken()
	for range 3 {
		expect(t, e.do("GET", "/api/1/configs", bad, nil), 401)
	}
	r := e.do("GET", "/api/1/configs", tok, nil)
	expect(t, r, 429)
	if r.Header.Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
}

// TestObjectLevelAuthorization checks that no endpoint lets one user reach
// another user's config (OWASP API1, BOLA).
func TestObjectLevelAuthorization(t *testing.T) {
	e := newEnv(t, nil)
	alice, _ := e.token(e.user("alice"))
	bob, _ := e.token(e.user("bob"))

	var c cfgJSON
	e.do("POST", "/api/1/configs", alice, map[string]any{"name": "secret", "content": "k: v"}).json(t, &c)
	path := fmt.Sprintf("/api/1/configs/%d", c.ID)

	expect(t, e.do("GET", path, bob, nil), 404)
	expect(t, e.do("PATCH", path, bob, map[string]any{"content": "pwned: 1"}), 404)
	expect(t, e.do("PUT", path, bob, map[string]any{"content": "pwned: 1"}), 404)
	expect(t, e.do("DELETE", path, bob, nil), 404)
	expect(t, e.do("PUT", "/api/1/user", bob, map[string]any{"active_config": c.ID}), 400)

	r := e.do("GET", "/api/1/configs", bob, nil)
	if strings.TrimSpace(string(r.body)) != "[]" {
		t.Fatalf("bob sees %s", r.body)
	}
	var still cfgJSON
	e.do("GET", path, alice, nil).json(t, &still)
	if still.Content != "k: v" {
		t.Fatalf("alice's config changed: %+v", still)
	}

	// Ignored read-only fields cannot move a config to another user.
	var bobUser map[string]any
	e.do("GET", "/api/1/user", bob, nil).json(t, &bobUser)
	expect(t, e.do("PATCH", path, alice, map[string]any{"user": bobUser["id"], "id": 999}), 200)
	expect(t, e.do("GET", path, alice, nil), 200)
	expect(t, e.do("GET", path, bob, nil), 404)
}

func TestActiveConfig(t *testing.T) {
	e := newEnv(t, nil)
	tok, _ := e.token(e.user("alice"))
	var c cfgJSON
	e.do("POST", "/api/1/configs", tok, map[string]any{}).json(t, &c)
	if !strings.HasPrefix(c.Name, "Unnamed config (") {
		t.Fatalf("default name %q", c.Name)
	}

	var u map[string]any
	r := e.do("PUT", "/api/1/user", tok, map[string]any{"active_config": c.ID, "username": "mallory", "config_sync_token": "x"})
	expect(t, r, 200)
	r.json(t, &u)
	if u["active_config"] != float64(c.ID) || u["username"] != "alice" {
		t.Fatalf("user %v", u)
	}
	expect(t, e.do("PUT", "/api/1/user", tok, map[string]any{"is_admin": true}), 400)

	// Deleting the active config clears it.
	expect(t, e.do("DELETE", fmt.Sprintf("/api/1/configs/%d", c.ID), tok, nil), 204)
	e.do("GET", "/api/1/user", tok, nil).json(t, &u)
	if u["active_config"] != nil {
		t.Fatalf("active_config = %v after delete", u["active_config"])
	}
	expect(t, e.do("PUT", "/api/1/user", tok, map[string]any{"active_config": c.ID}), 400)
}

func TestValidationAndLimits(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.MaxConfigBytes = 2048; c.Limits.MaxConfigsPerUser = 2 })
	tok, _ := e.token(e.user("alice"))

	for _, body := range []map[string]any{
		{"content": "[1,2]"},
		{"content": "a: [broken"},
		{"content": ""},
		{"name": ""},
		{"name": nil},
		{"name": strings.Repeat("n", 256)},
		{"last_used_with_version": strings.Repeat("1", 40)},
		{"unknown": 1},
		{"content": "a: " + strings.Repeat("x", 3000)},
	} {
		r := e.do("POST", "/api/1/configs", tok, body)
		if r.StatusCode != 400 && r.StatusCode != 413 {
			t.Errorf("%v: status %d %s", body, r.StatusCode, r.body)
		}
	}
	r := e.do("POST", "/api/1/configs", tok, nil, "Content-Type", "text/plain")
	expect(t, r, 415)
	// Beyond the body limit (2 × MaxConfigBytes + 64 KiB) the request is
	// cut off before decoding; below it oversized content fails validation.
	big := `{"content":"a: ` + strings.Repeat("x", 100000) + `"}`
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/1/configs", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 413 {
		t.Errorf("oversized body: %d", res.StatusCode)
	}

	expect(t, e.do("POST", "/api/1/configs", tok, map[string]any{}), 201)
	expect(t, e.do("POST", "/api/1/configs", tok, map[string]any{}), 201)
	expect(t, e.do("POST", "/api/1/configs", tok, map[string]any{}), 409)
	expect(t, e.do("GET", "/api/1/configs/abc", tok, nil), 404)
	expect(t, e.do("GET", "/api/1/configs/-1", tok, nil), 404)
}

func TestIfMatch(t *testing.T) {
	e := newEnv(t, nil)
	tok, _ := e.token(e.user("alice"))
	var c cfgJSON
	r := e.do("POST", "/api/1/configs", tok, map[string]any{"content": "a: 1"})
	r.json(t, &c)
	path := fmt.Sprintf("/api/1/configs/%d", c.ID)
	v1 := r.Header.Get("ETag")

	r = e.do("PATCH", path, tok, map[string]any{"content": "a: 2"}, "If-Match", v1)
	expect(t, r, 200)
	v2 := r.Header.Get("ETag")
	if v2 == v1 {
		t.Fatal("ETag did not change")
	}
	r = e.do("PATCH", path, tok, map[string]any{"content": "a: 3"}, "If-Match", v1)
	expect(t, r, 412)
	if r.Header.Get("ETag") != v2 {
		t.Fatalf("412 ETag %q, want %q", r.Header.Get("ETag"), v2)
	}
	var cur cfgJSON
	e.do("GET", path, tok, nil).json(t, &cur)
	if cur.Content != "a: 2" {
		t.Fatalf("stale write applied: %q", cur.Content)
	}
	expect(t, e.do("PATCH", path, tok, map[string]any{"content": "a: 3"}, "If-Match", `W/"v1"`), 400)
}

// TestConcurrentBlindWrites: the desktop client never sends If-Match, so
// concurrent writes cannot be rejected, but none of them may be lost.
func TestConcurrentBlindWrites(t *testing.T) {
	e := newEnv(t, nil)
	alice := e.user("alice")
	tok, _ := e.token(alice)
	var c cfgJSON
	e.do("POST", "/api/1/configs", tok, map[string]any{}).json(t, &c)
	path := fmt.Sprintf("/api/1/configs/%d", c.ID)

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.do("PATCH", path, tok, map[string]any{"content": fmt.Sprintf("writer: %d", i)})
			if r.StatusCode != 200 {
				errs <- fmt.Sprintf("writer %d: %d %s", i, r.StatusCode, r.body)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}

	cur, err := e.db.GetConfig(context.Background(), alice.ID, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.CurrentRevision != n+1 || cur.Version != n+1 {
		t.Fatalf("revision %d version %d, want %d", cur.CurrentRevision, cur.Version, n+1)
	}
	seen := history(t, e, alice.ID, c.ID)
	for i := range n {
		if !seen[fmt.Sprintf("writer: %d", i)] {
			t.Errorf("write %d lost from history", i)
		}
	}
}

// TestConcurrentConditionalWrites: with If-Match exactly one of several
// writers based on the same version wins.
func TestConcurrentConditionalWrites(t *testing.T) {
	e := newEnv(t, nil)
	tok, _ := e.token(e.user("alice"))
	r := e.do("POST", "/api/1/configs", tok, map[string]any{})
	var c cfgJSON
	r.json(t, &c)
	path := fmt.Sprintf("/api/1/configs/%d", c.ID)
	base := r.Header.Get("ETag")

	const n = 20
	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.do("PATCH", path, tok, map[string]any{"content": fmt.Sprintf("w: %d", i)}, "If-Match", base)
			mu.Lock()
			codes[r.StatusCode]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[200] != 1 || codes[412] != n-1 {
		t.Fatalf("status counts %v", codes)
	}
}

func history(t *testing.T, e *env, userID, configID int64) map[string]bool {
	t.Helper()
	pool := rawPool(t, e)
	rows, err := pool.Query(context.Background(),
		`SELECT revision, ciphertext, dek_wrapped, kek_id FROM config_revisions WHERE config_id = $1`, configID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var rev int32
		var s crypto.Sealed
		if err := rows.Scan(&rev, &s.Ciphertext, &s.WrappedDEK, &s.KEKID); err != nil {
			t.Fatal(err)
		}
		pt, err := e.keys.Open(s, crypto.Binding{UserID: userID, ConfigID: configID, Revision: rev})
		if err != nil {
			t.Fatal(err)
		}
		seen[string(pt)] = true
	}
	return seen
}

func TestSecurityHeadersAndCORS(t *testing.T) {
	e := newEnv(t, nil)
	tok, _ := e.token(e.user("alice"))
	r := e.do("GET", "/api/1/configs", tok, nil, "Origin", "file://")
	for h, want := range map[string]string{
		"Cache-Control":               "no-store",
		"X-Content-Type-Options":      "nosniff",
		"Access-Control-Allow-Origin": "*",
		"Content-Type":                "application/json",
	} {
		if got := r.Header.Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
	if r.Header.Get("X-Request-ID") == "" || r.Header.Get("Strict-Transport-Security") == "" {
		t.Error("missing X-Request-ID or HSTS")
	}
	if r.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Error("credentials must not be allowed")
	}

	r = e.do("OPTIONS", "/api/1/configs/1", "", nil,
		"Origin", "null", "Access-Control-Request-Method", "PATCH",
		"Access-Control-Request-Headers", "authorization,content-type")
	expect(t, r, 204)
	if !strings.Contains(r.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Errorf("preflight headers %v", r.Header)
	}

	expect(t, e.do("GET", "/healthz", "", nil), 200)
	expect(t, e.do("GET", "/readyz", "", nil), 200)
	r = e.do("GET", "/api/1/configs/999", tok, nil)
	expect(t, r, 404)
	if r.Header.Get("Content-Type") != "application/problem+json" {
		t.Errorf("error content type %q", r.Header.Get("Content-Type"))
	}
}
