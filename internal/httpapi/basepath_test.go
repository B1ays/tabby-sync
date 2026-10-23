package httpapi_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"tabbysync/internal/config"
)

const base = "/services/tabby-sync"

func TestAPIUnderBasePath(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.BasePath = base })
	tok, _ := e.token(e.user("alice"))

	expect(t, e.do("GET", "/api/1/configs", tok, nil), 404)
	expect(t, e.do("GET", "/healthz", "", nil), 404)
	r := e.do("GET", base+"/api/1/configs", tok, nil)
	expect(t, r, 200)
	if r.Header.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must not be set on a shared origin")
	}
	r = e.do("POST", base+"/api/1/configs", tok, map[string]any{"name": "x"})
	expect(t, r, 201)
	if loc := r.Header.Get("Location"); !strings.HasPrefix(loc, base+"/api/1/configs/") {
		t.Errorf("v1 Location %q", loc)
	}
	r = e.do("POST", base+"/api/2/configs", tok, map[string]any{"name": "y"}, "Idempotency-Key", `"k"`)
	expect(t, r, 201)
	if loc := r.Header.Get("Location"); !strings.HasPrefix(loc, base+"/api/2/configs/") {
		t.Errorf("v2 Location %q", loc)
	}

	// The bare prefix redirects to the prefix with a slash.
	c := *e.srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := c.Get(e.srv.URL + base)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 301 || res.Header.Get("Location") != base+"/" {
		t.Errorf("bare prefix: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	// The query string survives the redirect.
	res, err = c.Get(e.srv.URL + base + "?return_to=%2Fdevices&x=1")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if loc := res.Header.Get("Location"); loc != base+"/?return_to=%2Fdevices&x=1" {
		t.Errorf("bare prefix with query: %s", loc)
	}
}

func TestWebUnderBasePath(t *testing.T) {
	e := newWebEnv(t, func(c *config.Config) {
		c.BasePath = base
		c.PublicURL += base
	})
	b := e.browser()

	p := get(t, b, e.url+base+"/devices")
	if !strings.HasPrefix(p.url, e.url+base+"/login?return_to=%2Fdevices") {
		t.Fatalf("unauthenticated redirect: %s", p.url)
	}
	if !strings.Contains(p.body, `href="`+base+`/static/style.css"`) ||
		!strings.Contains(p.body, `href="`+base+`/auth/test/login?return_to=%2fdevices"`) {
		t.Fatalf("login page links lack the prefix:\n%s", p.body)
	}

	p = get(t, b, e.url+base+"/auth/test/login?return_to=/devices")
	if p.status != 200 || p.url != e.url+base+"/devices" {
		t.Fatalf("after login: %d %s", p.status, p.url)
	}
	for _, link := range []string{`action="` + base + `/logout"`, `href="` + base + `/configs"`, `action="` + base + `/devices"`} {
		if !strings.Contains(p.body, link) {
			t.Errorf("page lacks %s", link)
		}
	}

	// The session cookie is scoped to the prefix: other apps on the host
	// never receive it.
	cookies := func(path string) []*http.Cookie {
		u, err := url.Parse(e.url + path)
		if err != nil {
			t.Fatal(err)
		}
		return b.Jar.Cookies(u)
	}
	if c := cookies(base + "/configs"); len(c) != 1 || c[0].Name != "__Secure-tabbysync_session" {
		t.Fatalf("cookies under the prefix: %v", c)
	}
	for _, other := range []string{"/", "/services/x-panel/", "/services/tabby-sync-other/"} {
		if c := cookies(other); len(c) != 0 {
			t.Fatalf("cookie leaks to %s: %v", other, c)
		}
	}

	// Forms work under the prefix, and redirects stay in it.
	p = post(t, b, e.url+base+"/sessions/revoke-others", url.Values{"csrf": {csrf(t, p)}})
	if p.status != 200 || !strings.HasPrefix(p.url, e.url+base+"/devices") {
		t.Fatalf("form post: %d %s", p.status, p.url)
	}
	p = post(t, b, e.url+base+"/logout", url.Values{"csrf": {csrf(t, p)}})
	if p.url != e.url+base+"/login" {
		t.Fatalf("logout landed on %s", p.url)
	}
}
