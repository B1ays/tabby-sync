package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"tabbysync/internal/config"
)

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		remote string
		xff    []string
		want   string
	}{
		{"203.0.113.5:1234", nil, "203.0.113.5"},
		// Untrusted peer: the header is ignored.
		{"203.0.113.5:1234", []string{"1.2.3.4"}, "203.0.113.5"},
		{"10.0.0.2:80", []string{"198.51.100.7"}, "198.51.100.7"},
		// Client-supplied entries left of the proxy's own are not believed.
		{"10.0.0.2:80", []string{"6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		{"10.0.0.2:80", []string{"6.6.6.6", "198.51.100.7, 10.0.0.9"}, "198.51.100.7"},
		{"10.0.0.2:80", []string{"garbage"}, "10.0.0.2"},
		{"[::ffff:10.0.0.2]:80", []string{"198.51.100.7"}, "198.51.100.7"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientIP(r, trusted).String(); got != c.want {
			t.Errorf("%s %v: got %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestParseIfMatch(t *testing.T) {
	for v, want := range map[string]int64{"": 0, "*": 0, `"v12"`: 12} {
		r := httptest.NewRequest("PATCH", "/", nil)
		r.Header.Set("If-Match", v)
		got, err := parseIfMatch(r)
		if err != nil || (want == 0) == got.Set || got.Value != want {
			t.Errorf("%q: %+v %v", v, got, err)
		}
	}
	for _, v := range []string{`W/"v1"`, `"v0"`, `"x1"`, `"v1", "v2"`, `"v"`, `v1`} {
		r := httptest.NewRequest("PATCH", "/", nil)
		r.Header.Set("If-Match", v)
		if _, err := parseIfMatch(r); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestDecodeJSON(t *testing.T) {
	type dst struct {
		Name    optString     `json:"name"`
		Version optNullString `json:"v"`
	}
	cases := []struct {
		ct, body string
		status   int
	}{
		{"application/json", `{"name":"a"}`, 0},
		{"application/json; charset=utf-8", `{"v":null}`, 0},
		{"text/plain", `{"name":"a"}`, http.StatusUnsupportedMediaType},
		{"application/json", `{"name":null}`, http.StatusBadRequest},
		{"application/json", `{"nope":1}`, http.StatusBadRequest},
		{"application/json", `{"name":1}`, http.StatusBadRequest},
		{"application/json", `{"name":"a"} {}`, http.StatusBadRequest},
		{"application/json", `{"name":"` + strings.Repeat("x", 200) + `"}`, http.StatusRequestEntityTooLarge},
		{"application/json", `{`, http.StatusBadRequest},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/", strings.NewReader(c.body))
		r.Header.Set("Content-Type", c.ct)
		var d dst
		err := decodeJSON(httptest.NewRecorder(), r, 100, &d)
		var be *bodyError
		switch {
		case c.status == 0 && err != nil:
			t.Errorf("%s: unexpected %v", c.body, err)
		case c.status != 0 && (!errors.As(err, &be) || be.status != c.status):
			t.Errorf("%s: err = %v, want status %d", c.body, err, c.status)
		}
	}
}

func TestKeyedLimiter(t *testing.T) {
	l := newKeyedLimiter(0.001, 2)
	for i, want := range []bool{true, true, false} {
		if got := l.Allow("a"); got != want {
			t.Fatalf("request %d: Allow = %v", i, got)
		}
	}
	if !l.Exhausted("a") || l.Exhausted("b") {
		t.Fatal("Exhausted wrong")
	}
	if !l.Allow("b") {
		t.Fatal("keys not independent")
	}
	l.max = 2
	if l.Allow("c") {
		t.Fatal("cap not enforced")
	}
}

func TestCORSPreflight(t *testing.T) {
	s := &Server{cfg: &config.Config{CORSOrigins: []string{"https://app.example"}}}
	h := s.cors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) }))

	pre := func(origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("OPTIONS", "/api/1/configs", nil)
		r.Header.Set("Origin", origin)
		r.Header.Set("Access-Control-Request-Method", "PATCH")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := pre("https://app.example"); w.Code != 204 ||
		w.Header().Get("Access-Control-Allow-Origin") != "https://app.example" ||
		w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("allowed origin: %d %v", w.Code, w.Header())
	}
	if w := pre("https://evil.example"); w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("foreign origin: %d %v", w.Code, w.Header())
	}
}

func TestBearer(t *testing.T) {
	for v, want := range map[string]string{
		"Bearer abc":   "abc",
		"bearer  abc ": "abc",
		"Basic abc":    "",
		"Bearer":       "",
		"":             "",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", v)
		if got, _ := bearer(r); got != want {
			t.Errorf("%q: got %q", v, got)
		}
	}
}
