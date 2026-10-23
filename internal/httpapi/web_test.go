package httpapi_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"tabbysync/internal/auth"
	"tabbysync/internal/config"
	"tabbysync/internal/configs"
	"tabbysync/internal/crypto"
	"tabbysync/internal/httpapi"
	"tabbysync/internal/store"
	"tabbysync/internal/testdb"
)

type webEnv struct {
	t     *testing.T
	db    *store.Store
	dbURL string
	svc   *configs.Service
	idp   *fakeIdP
	srv   *httptest.Server
	url   string
}

func newWebEnv(t *testing.T, mod func(*config.Config)) *webEnv {
	t.Helper()
	db, dbURL := testdb.Open(t)
	line, _ := crypto.GenerateKeyLine("k1")
	keys, _ := crypto.ParseKeyring(strings.NewReader(line), "k1")
	idp := newFakeIdP(t)

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	cfg := &config.Config{
		CORSOrigins: []string{"*"},
		PublicURL:   srv.URL,
		OIDC: []config.OIDCProvider{{
			ID: "test", Name: "Test IdP", Issuer: idp.srv.URL,
			ClientID: idpClientID, ClientSecret: idpClientSecret, Scopes: []string{"openid", "email"},
		}},
		AllowedEmailDomains: []string{"example.com"},
		Session:             config.Session{Idle: 30 * time.Minute, MaxAge: 12 * time.Hour, ReauthMaxAge: 15 * time.Minute},
		Limits:              config.Limits{MaxConfigBytes: 64 << 10, MaxConfigsPerUser: 5},
		Retention:           config.Retention{KeepMin: 1000, MaxAge: time.Hour, HardCap: 10000},
		RateLimit: config.RateLimit{IPRate: 1e4, IPBurst: 1e4, AuthFailPerMinute: 1e4, AuthFailBurst: 1e4,
			DeviceRate: 1e4, DeviceBurst: 1e4},
	}
	if mod != nil {
		mod(cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &configs.Service{DB: db, Keys: keys, Log: log,
		Limits:    configs.Limits{MaxConfigBytes: 64 << 10, MaxConfigsPerUser: 5},
		Retention: store.Retention{KeepMin: 1000, MaxAge: time.Hour, HardCap: 10000}}
	srv.Config.Handler = httpapi.New(cfg, log, db, svc, httpapi.WithOIDCClient(idp.srv.Client())).Handler()
	return &webEnv{t: t, db: db, dbURL: dbURL, svc: svc, idp: idp, srv: srv, url: srv.URL}
}

// browser returns a client with its own cookie jar; it follows redirects
// unless stopAt matches the path about to be requested.
func (e *webEnv) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	c := e.srv.Client()
	return &http.Client{Transport: c.Transport, Jar: jar}
}

func noFollow(c *http.Client) *http.Client {
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

type page struct {
	status int
	url    string
	body   string
	header http.Header
}

func get(t *testing.T, c *http.Client, u string) page {
	t.Helper()
	res, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return page{res.StatusCode, res.Request.URL.String(), string(b), res.Header}
}

func post(t *testing.T, c *http.Client, u string, form url.Values, headers ...string) page {
	t.Helper()
	req, _ := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return page{res.StatusCode, res.Request.URL.String(), string(b), res.Header}
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrf(t *testing.T, p page) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no csrf token on %s", p.url)
	}
	return m[1]
}

// login runs the whole browser flow and returns the landing page.
func (e *webEnv) login(c *http.Client, returnTo string) page {
	e.t.Helper()
	return get(e.t, c, e.url+"/auth/test/login?return_to="+url.QueryEscape(returnTo))
}

func TestWebLoginFlow(t *testing.T) {
	e := newWebEnv(t, nil)
	b := e.browser()

	// Not signed in: protected pages redirect to the login page.
	p := get(t, b, e.url+"/devices")
	if !strings.Contains(p.url, "/login?return_to=%2Fdevices") || !strings.Contains(p.body, "Войти через Test IdP") {
		t.Fatalf("unauthenticated: %s %s", p.url, p.body)
	}

	p = e.login(b, "/devices")
	if p.status != 200 || !strings.HasSuffix(p.url, "/devices") || !strings.Contains(p.body, "alice@example.com") {
		t.Fatalf("after login: %d %s", p.status, p.url)
	}
	if csp := p.header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
		t.Errorf("CSP %q", csp)
	}
	u, err := e.db.UserByIdentity(context.Background(), e.idp.srv.URL, "user-1")
	if err != nil || u.Username != "alice@example.com" {
		t.Fatalf("user %+v %v", u, err)
	}

	// The same identity with a changed email is still the same user.
	e.idp.set(func(f *fakeIdP) { f.Email = "renamed@other.org" })
	p = e.login(e.browser(), "/configs")
	if p.status != 200 || !strings.Contains(p.body, "alice@example.com") {
		t.Fatalf("relogin: %d %s", p.status, p.body)
	}

	// Logout ends the session server-side.
	p = get(t, b, e.url+"/devices")
	p = post(t, b, e.url+"/logout", url.Values{"csrf": {csrf(t, p)}})
	if !strings.HasSuffix(p.url, "/login") {
		t.Fatalf("logout landed on %s", p.url)
	}
	if p := get(t, b, e.url+"/configs"); !strings.Contains(p.url, "/login") {
		t.Fatal("still signed in after logout")
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	e := newWebEnv(t, nil)
	b := noFollow(e.browser())
	res, err := b.Get(e.url + "/auth/test/login")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	flowSet := res.Header.Get("Set-Cookie")
	authURL := res.Header.Get("Location")
	for _, attr := range []string{"__Host-tabbysync_flow=", "Path=/", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(flowSet, attr) {
			t.Errorf("flow cookie %q lacks %s", flowSet, attr)
		}
	}
	au, _ := url.Parse(authURL)
	if au.Query().Get("code_challenge_method") != "S256" || au.Query().Get("nonce") == "" {
		t.Fatalf("authorize URL %s", authURL)
	}
	res, _ = b.Get(authURL)
	res.Body.Close()
	res, err = b.Get(res.Header.Get("Location")) // the callback
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	var session string
	for _, c := range res.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, "__Host-tabbysync_session=") {
			session = c
		}
	}
	for _, attr := range []string{"Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age="} {
		if !strings.Contains(session, attr) {
			t.Errorf("session cookie %q lacks %s", session, attr)
		}
	}
	if strings.Contains(session, "Domain=") {
		t.Error("session cookie must not set Domain")
	}
}

// startFlow begins a login and returns the IdP's redirect back to us
// (callback URL with code and state) without following it.
func (e *webEnv) startFlow(b *http.Client) string {
	e.t.Helper()
	nf := noFollow(b)
	res, err := nf.Get(e.url + "/auth/test/login")
	if err != nil {
		e.t.Fatal(err)
	}
	res.Body.Close()
	res, err = nf.Get(res.Header.Get("Location"))
	if err != nil {
		e.t.Fatal(err)
	}
	res.Body.Close()
	return res.Header.Get("Location")
}

func TestCallbackAttacks(t *testing.T) {
	e := newWebEnv(t, nil)

	t.Run("tampered state", func(t *testing.T) {
		b := e.browser()
		cb, _ := url.Parse(e.startFlow(b))
		q := cb.Query()
		q.Set("state", "forged")
		cb.RawQuery = q.Encode()
		if p := get(t, b, cb.String()); p.status != 400 {
			t.Fatalf("status %d", p.status)
		}
	})

	t.Run("replayed callback", func(t *testing.T) {
		b := e.browser()
		cb := e.startFlow(b)
		if p := get(t, b, cb); p.status != 200 {
			t.Fatalf("first: %d %s", p.status, p.body)
		}
		if p := get(t, b, cb); p.status != 400 {
			t.Fatalf("replay: %d", p.status)
		}
	})

	t.Run("login CSRF: attacker's callback in victim's browser", func(t *testing.T) {
		attacker, victim := e.browser(), e.browser()
		cb := e.startFlow(attacker)
		if p := get(t, victim, cb); p.status != 400 {
			t.Fatalf("victim logged in via forged callback: %d", p.status)
		}
	})

	t.Run("code from another flow (PKCE)", func(t *testing.T) {
		attacker, victim := e.browser(), e.browser()
		stolen, _ := url.Parse(e.startFlow(attacker))
		own, _ := url.Parse(e.startFlow(victim))
		q := own.Query()
		q.Set("code", stolen.Query().Get("code"))
		own.RawQuery = q.Encode()
		if p := get(t, victim, own.String()); p.status != 400 {
			t.Fatalf("status %d", p.status)
		}
	})

	for name, knob := range map[string]func(*fakeIdP){
		"wrong nonce":    func(f *fakeIdP) { f.BadNonce = true },
		"wrong audience": func(f *fakeIdP) { f.BadAudience = true },
		"expired token":  func(f *fakeIdP) { f.Expired = true },
		"bad signature":  func(f *fakeIdP) { f.WrongKey = true },
	} {
		t.Run(name, func(t *testing.T) {
			e.idp.set(knob)
			defer e.idp.set(func(f *fakeIdP) { f.BadNonce, f.BadAudience, f.Expired, f.WrongKey = false, false, false, false })
			if p := e.login(e.browser(), "/"); p.status != 400 {
				t.Fatalf("status %d", p.status)
			}
		})
	}

	t.Run("open redirect", func(t *testing.T) {
		for _, rt := range []string{"//evil.example/x", "https://evil.example", "/\\evil.example", "javascript:alert(1)"} {
			p := e.login(e.browser(), rt)
			if p.status != 200 || !strings.HasPrefix(p.url, e.url+"/configs") {
				t.Errorf("return_to %q landed on %s", rt, p.url)
			}
		}
	})
}

func TestSignupPolicy(t *testing.T) {
	e := newWebEnv(t, nil)
	ctx := context.Background()

	cases := []struct {
		sub, email string
		verified   any
		status     int
	}{
		{"s1", "mallory@evil.org", true, 403},    // not on the allow-list
		{"s2", "eve@example.com", false, 403},    // unverified email
		{"s3", "eve@example.com", "false", 403},  // string form, unverified
		{"s4", "Carol@Example.com", "true", 200}, // string form, verified; case-insensitive
		{"s5", "not an email", true, 403},
	}
	for _, c := range cases {
		e.idp.set(func(f *fakeIdP) { f.Sub, f.Email, f.Verified = c.sub, c.email, c.verified })
		if p := e.login(e.browser(), "/"); p.status != c.status {
			t.Errorf("%s %v: status %d, want %d", c.email, c.verified, p.status, c.status)
		}
	}

	// An admin-registered email outside the allow-list links on first login...
	if _, err := e.db.CreateUserWithEmail(ctx, "bob", ptr("bob@corp.test")); err != nil {
		t.Fatal(err)
	}
	e.idp.set(func(f *fakeIdP) { f.Sub, f.Email, f.Verified = "bob-sub", "bob@corp.test", true })
	if p := e.login(e.browser(), "/"); p.status != 200 || !strings.Contains(p.body, ">bob<") {
		t.Fatalf("bob: %d", p.status)
	}
	// ...but only once: another identity claiming the same email is refused.
	e.idp.set(func(f *fakeIdP) { f.Sub = "imposter" })
	if p := e.login(e.browser(), "/"); p.status != 403 {
		t.Fatalf("imposter: %d", p.status)
	}

	// Disabled users cannot sign in.
	bob, _ := e.db.GetUserByUsername(ctx, "bob")
	_ = e.db.SetUserDisabled(ctx, bob.ID, true)
	e.idp.set(func(f *fakeIdP) { f.Sub = "bob-sub" })
	if p := e.login(e.browser(), "/"); p.status != 403 {
		t.Fatalf("disabled: %d", p.status)
	}
}

func ptr[T any](v T) *T { return &v }

func TestSessionExpiry(t *testing.T) {
	e := newWebEnv(t, nil)
	ctx := context.Background()
	pool := rawPool(t, &env{url: e.dbURL})
	for name, q := range map[string]string{
		"idle":     `UPDATE sessions SET last_seen_at = now() - interval '31 minutes'`,
		"absolute": `UPDATE sessions SET expires_at = now() - interval '1 second'`,
		"disabled": `UPDATE users SET disabled_at = now()`,
	} {
		t.Run(name, func(t *testing.T) {
			_, _ = pool.Exec(ctx, `UPDATE users SET disabled_at = NULL`)
			b := e.browser()
			if p := e.login(b, "/configs"); p.status != 200 {
				t.Fatalf("login %d", p.status)
			}
			if _, err := pool.Exec(ctx, q); err != nil {
				t.Fatal(err)
			}
			if p := get(t, b, e.url+"/configs"); !strings.Contains(p.url, "/login") {
				t.Fatalf("session still valid: %s", p.url)
			}
		})
	}
}

func TestCSRF(t *testing.T) {
	e := newWebEnv(t, nil)
	b := e.browser()
	p := e.login(b, "/devices")
	token := csrf(t, p)

	if p := post(t, b, e.url+"/sessions/revoke-others", url.Values{}); p.status != 403 {
		t.Errorf("no token: %d", p.status)
	}
	if p := post(t, b, e.url+"/sessions/revoke-others", url.Values{"csrf": {"x" + token}}); p.status != 403 {
		t.Errorf("wrong token: %d", p.status)
	}
	if p := post(t, b, e.url+"/sessions/revoke-others", url.Values{"csrf": {token}},
		"Sec-Fetch-Site", "cross-site"); p.status != 403 {
		t.Errorf("cross-site with valid token: %d", p.status)
	}
	if p := post(t, b, e.url+"/sessions/revoke-others", url.Values{"csrf": {token}},
		"Origin", "https://evil.example"); p.status != 403 {
		t.Errorf("foreign Origin with valid token: %d", p.status)
	}
	// Another user's token is useless.
	other := e.browser()
	e.idp.set(func(f *fakeIdP) { f.Sub, f.Email = "u2", "dave@example.com" })
	otherTok := csrf(t, e.login(other, "/devices"))
	if p := post(t, b, e.url+"/sessions/revoke-others", url.Values{"csrf": {otherTok}}); p.status != 403 {
		t.Errorf("other session's token: %d", p.status)
	}
	if p := post(t, b, e.url+"/sessions/revoke-others", url.Values{"csrf": {token}},
		"Sec-Fetch-Site", "same-origin"); p.status != 200 || !strings.HasSuffix(p.url, "/devices?flash=revoked") {
		t.Errorf("valid: %d %s", p.status, p.url)
	}
}

var tokenRe = regexp.MustCompile(`<pre class="token">(tbs_[A-Za-z0-9_-]+)</pre>`)

func TestDeviceManagement(t *testing.T) {
	e := newWebEnv(t, nil)
	b := e.browser()
	p := e.login(b, "/devices")

	p = post(t, b, e.url+"/devices", url.Values{
		"csrf": {csrf(t, p)}, "name": {"Ноутбук"}, "scope": {"configs:read", "configs:write"}, "ttl": {"720h"},
	})
	m := tokenRe.FindStringSubmatch(p.body)
	if p.status != 200 || m == nil || p.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %s", p.status, p.body)
	}
	token := m[1]

	api := func() int {
		req, _ := http.NewRequest("GET", e.url+"/api/1/configs", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := e.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if s := api(); s != 200 {
		t.Fatalf("new token: %d", s)
	}

	// The token is not on the listing page, only its hint.
	p = get(t, b, e.url+"/devices")
	if strings.Contains(p.body, token) || !strings.Contains(p.body, auth.Hint(token)) {
		t.Fatal("listing must show the hint only")
	}
	devs, _ := e.db.ListDevices(context.Background(), 1)
	p = post(t, b, e.url+"/devices/"+devs[0].ID.String()+"/revoke", url.Values{"csrf": {csrf(t, p)}})
	if p.status != 200 || api() != 401 {
		t.Fatalf("revoke: %d, api %d", p.status, api())
	}

	// Invalid input.
	for _, form := range []url.Values{
		{"name": {""}, "scope": {"configs:read"}, "ttl": {"720h"}},
		{"name": {"x"}, "scope": {"root"}, "ttl": {"720h"}},
		{"name": {"x"}, "scope": {"configs:read"}, "ttl": {"999999h"}},
	} {
		form.Set("csrf", csrf(t, get(t, b, e.url+"/devices")))
		if p := post(t, b, e.url+"/devices", form); p.status != 400 {
			t.Errorf("%v: %d", form, p.status)
		}
	}
}

func TestReauthForTokenIssue(t *testing.T) {
	e := newWebEnv(t, nil)
	b := e.browser()
	p := e.login(b, "/devices")
	pool := rawPool(t, &env{url: e.dbURL})
	if _, err := pool.Exec(context.Background(), `UPDATE sessions SET authenticated_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"csrf": {csrf(t, p)}, "name": {"x"}, "scope": {"configs:read"}, "ttl": {"720h"}}
	p = post(t, b, e.url+"/devices", form)
	if p.status != 403 || !strings.Contains(p.body, "reauth=1") {
		t.Fatalf("stale login: %d", p.status)
	}

	// The IdP silently reuses an old SSO session: not good enough.
	if p := get(t, b, e.url+"/auth/test/login?reauth=1&return_to=/devices"); p.status != 403 {
		t.Fatalf("reauth without fresh auth_time: %d", p.status)
	}
	// A fresh authentication passes, and gives a new session.
	e.idp.set(func(f *fakeIdP) { f.AuthTime = time.Now() })
	p = get(t, b, e.url+"/auth/test/login?reauth=1&return_to=/devices")
	if p.status != 200 {
		t.Fatalf("reauth: %d %s", p.status, p.body)
	}
	form.Set("csrf", csrf(t, p))
	if p := post(t, b, e.url+"/devices", form); p.status != 200 || !tokenRe.MatchString(p.body) {
		t.Fatalf("after reauth: %d", p.status)
	}
}

func TestHistoryAndRestore(t *testing.T) {
	e := newWebEnv(t, nil)
	b := e.browser()
	e.login(b, "/")
	ctx := context.Background()
	alice, _ := e.db.UserByIdentity(ctx, e.idp.srv.URL, "user-1")
	a := auth.Actor{UserID: alice.ID}

	c, _ := e.svc.Create(ctx, a, configs.Patch{Name: configs.Some(`<script>alert(1)</script>`), Content: configs.Some("v: 1")})
	_, _ = e.svc.Update(ctx, a, c.ID, configs.Patch{Content: configs.Some("v: 2\nx: </pre><script>alert(2)</script>")})
	_, _ = e.svc.Update(ctx, a, c.ID, configs.Patch{Content: configs.Some("v: 3")})

	p := get(t, b, fmt.Sprintf("%s/configs/%d", e.url, c.ID))
	if p.status != 200 || strings.Contains(p.body, "<script>") || !strings.Contains(p.body, "&lt;script&gt;") {
		t.Fatalf("history page: %d, escaping broken", p.status)
	}
	p = get(t, b, fmt.Sprintf("%s/configs/%d/revisions/2", e.url, c.ID))
	if p.status != 200 || strings.Contains(p.body, "<script>") || !strings.Contains(p.body, "v: 2") {
		t.Fatalf("revision page: %d", p.status)
	}

	// Restore with a stale version is refused.
	tok := csrf(t, p)
	p = post(t, b, fmt.Sprintf("%s/configs/%d/revisions/1/restore", e.url, c.ID), url.Values{"csrf": {tok}, "version": {"1"}})
	if !strings.Contains(p.url, "flash=changed") {
		t.Fatalf("stale restore landed on %s", p.url)
	}
	cur, _ := e.svc.Get(ctx, a, c.ID)
	p = post(t, b, fmt.Sprintf("%s/configs/%d/revisions/1/restore", e.url, c.ID),
		url.Values{"csrf": {tok}, "version": {fmt.Sprint(cur.Version)}})
	if !strings.Contains(p.url, "flash=restored") {
		t.Fatalf("restore landed on %s", p.url)
	}
	after, _ := e.svc.Get(ctx, a, c.ID)
	if after.Content != "v: 1" || after.Revision != 4 {
		t.Fatalf("after restore: %q rev %d", after.Content, after.Revision)
	}
	revs, _ := e.svc.Revisions(ctx, a, c.ID)
	if len(revs) != 4 {
		t.Fatalf("history has %d revisions", len(revs))
	}
	// The listing shows the size of the current revision without decrypting.
	if p := get(t, b, e.url+"/configs"); !strings.Contains(p.body, "<td>4 Б</td>") {
		t.Fatalf("configs page lacks the size of %q:\n%s", after.Content, p.body)
	}
}

func TestWebObjectLevelAuthorization(t *testing.T) {
	e := newWebEnv(t, nil)
	ctx := context.Background()
	alice := e.browser()
	e.login(alice, "/")
	aliceU, _ := e.db.UserByIdentity(ctx, e.idp.srv.URL, "user-1")
	c, _ := e.svc.Create(ctx, auth.Actor{UserID: aliceU.ID}, configs.Patch{Content: configs.Some("secret: 1")})
	_, _ = e.svc.Update(ctx, auth.Actor{UserID: aliceU.ID}, c.ID, configs.Patch{Content: configs.Some("secret: 2")})
	tok, hash, hint, _ := auth.NewToken()
	_ = tok
	dev, _ := e.db.CreateDevice(ctx, store.Device{ID: uuid.New(), UserID: aliceU.ID, Name: "a", TokenHint: hint, Scopes: auth.AllScopes}, hash)
	sessions, _ := e.db.ListSessions(ctx, aliceU.ID)

	bob := e.browser()
	e.idp.set(func(f *fakeIdP) { f.Sub, f.Email = "bob", "bob@example.com" })
	p := e.login(bob, "/devices")
	tokB := csrf(t, p)

	for _, u := range []string{
		fmt.Sprintf("/configs/%d", c.ID),
		fmt.Sprintf("/configs/%d/revisions/1", c.ID),
	} {
		if p := get(t, bob, e.url+u); p.status != 404 || strings.Contains(p.body, "secret") {
			t.Errorf("GET %s: %d", u, p.status)
		}
	}
	for _, u := range []string{
		fmt.Sprintf("/configs/%d/revisions/1/restore", c.ID),
		"/devices/" + dev.ID.String() + "/revoke",
		"/sessions/" + sessions[0].ID.String() + "/revoke",
	} {
		if p := post(t, bob, e.url+u, url.Values{"csrf": {tokB}, "version": {"2"}}); p.status != 404 {
			t.Errorf("POST %s: %d", u, p.status)
		}
	}
	cur, _ := e.svc.Get(ctx, auth.Actor{UserID: aliceU.ID}, c.ID)
	d, _ := e.db.ListDevices(ctx, aliceU.ID)
	if cur.Content != "secret: 2" || d[0].RevokedAt != nil {
		t.Fatal("bob changed alice's data")
	}
	if p := get(t, alice, e.url+"/configs"); p.status != 200 || strings.Contains(p.url, "/login") {
		t.Fatal("alice's session was ended by bob")
	}
}

func TestAPIIgnoresSessionCookie(t *testing.T) {
	e := newWebEnv(t, nil)
	b := e.browser()
	e.login(b, "/")
	res, err := b.Get(e.url + "/api/1/configs")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("cookie authenticated the bearer API: %d", res.StatusCode)
	}
}
