package httpapi_test

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type metaV2 struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Version       int64  `json:"version"`
	Revision      int32  `json:"revision"`
	Size          int    `json:"size"`
	ContentDigest string `json:"content_digest"`
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// raw sends a non-JSON body.
func (e *env) raw(method, path, token, contentType, body string, headers ...string) resp {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)
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

func (e *env) createV2(tok, content string) (metaV2, string) {
	e.t.Helper()
	r := e.do("POST", "/api/2/configs", tok, map[string]any{"name": "c", "content": content},
		"Idempotency-Key", fmt.Sprintf("%q", randKey()))
	expect(e.t, r, 201)
	var m metaV2
	r.json(e.t, &m)
	return m, r.Header.Get("ETag")
}

var keyN struct {
	sync.Mutex
	n int
}

func randKey() string {
	keyN.Lock()
	defer keyN.Unlock()
	keyN.n++
	return fmt.Sprintf("key-%d", keyN.n)
}

func TestV2ContentRoundTrip(t *testing.T) {
	e := newEnv(t, nil)
	tok, _ := e.token(e.user("alice"))
	m, tag := e.createV2(tok, "a: 1\n")
	if m.ContentDigest != digest("a: 1\n") || m.Size != 5 || tag != `"v1"` {
		t.Fatalf("created %+v %s", m, tag)
	}
	path := fmt.Sprintf("/api/2/configs/%d/content", m.ID)

	r := e.do("GET", path, tok, nil)
	expect(t, r, 200)
	if string(r.body) != "a: 1\n" || r.Header.Get("Repr-Digest") != digest("a: 1\n") ||
		!strings.HasPrefix(r.Header.Get("Content-Type"), "application/yaml") {
		t.Fatalf("GET content %q %v", r.body, r.Header)
	}
	expect(t, e.do("GET", path, tok, nil, "If-None-Match", tag), 304)

	content := "a: 2\nb: [x, y]\n"
	r = e.raw("PUT", path, tok, "application/yaml", content, "If-Match", tag, "Content-Digest", digest(content))
	expect(t, r, 200)
	var up metaV2
	r.json(t, &up)
	if up.Revision != 2 || up.ContentDigest != digest(content) || r.Header.Get("Repr-Digest") != digest(content) ||
		r.Header.Get("ETag") != `"v2"` {
		t.Fatalf("PUT %+v %v", up, r.Header)
	}
	r = e.do("GET", path, tok, nil, "If-None-Match", tag)
	if r.StatusCode != 200 || string(r.body) != content {
		t.Fatalf("stale If-None-Match: %d %q", r.StatusCode, r.body)
	}
}

func TestV2RequiresIfMatch(t *testing.T) {
	e := newEnv(t, nil)
	tok, _ := e.token(e.user("alice"))
	m, tag := e.createV2(tok, "a: 1")
	base := fmt.Sprintf("/api/2/configs/%d", m.ID)

	for _, c := range []struct{ method, path, ct, body string }{
		{"PUT", base + "/content", "application/yaml", "a: 2"},
		{"PATCH", base, "application/json", `{"name":"n"}`},
		{"DELETE", base, "application/json", ""},
		{"POST", base + "/revisions/1/restore", "application/json", ""},
	} {
		if r := e.raw(c.method, c.path, tok, c.ct, c.body); r.StatusCode != 428 {
			t.Errorf("%s %s without If-Match: %d", c.method, c.path, r.StatusCode)
		}
		if r := e.raw(c.method, c.path, tok, c.ct, c.body, "If-Match", "*"); r.StatusCode != 400 {
			t.Errorf("%s %s with *: %d", c.method, c.path, r.StatusCode)
		}
		if r := e.raw(c.method, c.path, tok, c.ct, c.body, "If-Match", `"v99"`); r.StatusCode != 412 || r.Header.Get("ETag") != tag {
			t.Errorf("%s %s stale: %d %s", c.method, c.path, r.StatusCode, r.Header.Get("ETag"))
		}
	}
	r := e.do("GET", base+"/content", tok, nil)
	if string(r.body) != "a: 1" {
		t.Fatalf("content changed: %q", r.body)
	}
}

func TestV2ContentDigestMismatch(t *testing.T) {
	e := newEnv(t, nil)
	tok, _ := e.token(e.user("alice"))
	m, tag := e.createV2(tok, "a: 1")
	path := fmt.Sprintf("/api/2/configs/%d/content", m.ID)

	for name, h := range map[string][]string{
		"wrong sha-256":       {"Content-Digest", digest("a: 3")},
		"wrong repr":          {"Repr-Digest", digest("other")},
		"malformed":           {"Content-Digest", "sha-256=abc"},
		"bad base64":          {"Content-Digest", "sha-256=:!!!:"},
		"one of two is wrong": {"Content-Digest", digest("a: 2") + ", sha-512=:AAAA:"},
	} {
		if r := e.raw("PUT", path, tok, "application/yaml", "a: 2", "If-Match", tag, h[0], h[1]); r.StatusCode != 400 {
			t.Errorf("%s: %d", name, r.StatusCode)
		}
	}
	// Unknown algorithms are ignored.
	r := e.raw("PUT", path, tok, "application/yaml", "a: 2", "If-Match", tag, "Content-Digest", "md5=:AAAA:")
	expect(t, r, 200)
	expect(t, e.raw("PUT", path, tok, "application/yaml", "a: 3", "If-Match", r.Header.Get("ETag"),
		"Content-Encoding", "gzip"), 415)
	expect(t, e.raw("PUT", path, tok, "image/png", "a: 3", "If-Match", r.Header.Get("ETag")), 415)
	expect(t, e.raw("PUT", path, tok, "application/yaml", "[1, 2]", "If-Match", r.Header.Get("ETag")), 400)
}

func TestV2IdempotentCreate(t *testing.T) {
	e := newEnv(t, nil)
	alice := e.user("alice")
	tok, _ := e.token(alice)

	expect(t, e.do("POST", "/api/2/configs", tok, map[string]any{"name": "x"}), 400)
	expect(t, e.do("POST", "/api/2/configs", tok, map[string]any{"name": "x"}, "Idempotency-Key", `"bad key"`), 400)

	body := map[string]any{"name": "laptop", "content": "a: 1"}
	r1 := e.do("POST", "/api/2/configs", tok, body, "Idempotency-Key", `"k-1"`)
	expect(t, r1, 201)
	r2 := e.do("POST", "/api/2/configs", tok, body, "Idempotency-Key", `"k-1"`)
	expect(t, r2, 201)
	if string(r1.body) != string(r2.body) || r2.Header.Get("Idempotent-Replayed") != "true" ||
		r2.Header.Get("Location") != r1.Header.Get("Location") || r1.Header.Get("Idempotent-Replayed") != "" {
		t.Fatalf("replay differs: %s / %s", r1.body, r2.body)
	}
	// Same key, different request.
	expect(t, e.do("POST", "/api/2/configs", tok, map[string]any{"name": "other"}, "Idempotency-Key", `"k-1"`), 422)

	// Keys are per user.
	bobTok, _ := e.token(e.user("bob"))
	expect(t, e.do("POST", "/api/2/configs", bobTok, body, "Idempotency-Key", `"k-1"`), 201)

	if n := countConfigs(t, e, alice.ID); n != 1 {
		t.Fatalf("alice has %d configs", n)
	}

	// Client errors are recorded and replayed too.
	bad := map[string]any{"content": "[not a mapping]"}
	expect(t, e.do("POST", "/api/2/configs", tok, bad, "Idempotency-Key", `"k-2"`), 400)
	r := e.do("POST", "/api/2/configs", tok, bad, "Idempotency-Key", `"k-2"`)
	if r.StatusCode != 400 || r.Header.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("error replay: %d %v", r.StatusCode, r.Header)
	}

	// An expired key is processed again.
	pool := rawPool(t, e)
	if _, err := pool.Exec(t.Context(), `UPDATE idempotency_keys SET expires_at = now() - interval '1 second' WHERE key = 'k-1'`); err != nil {
		t.Fatal(err)
	}
	r = e.do("POST", "/api/2/configs", tok, body, "Idempotency-Key", `"k-1"`)
	if r.StatusCode != 201 || r.Header.Get("Idempotent-Replayed") != "" || countConfigs(t, e, alice.ID) != 2 {
		t.Fatalf("expired key: %d %v", r.StatusCode, r.Header)
	}
}

func countConfigs(t *testing.T, e *env, userID int64) int {
	t.Helper()
	var n int
	if err := rawPool(t, e).QueryRow(t.Context(),
		`SELECT count(*) FROM configs WHERE user_id = $1 AND deleted_at IS NULL`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestV2ConcurrentIdempotentCreate: retries racing each other still create
// exactly one config and all get the same answer.
func TestV2ConcurrentIdempotentCreate(t *testing.T) {
	e := newEnv(t, nil)
	alice := e.user("alice")
	tok, _ := e.token(alice)
	const n = 15
	bodies := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.do("POST", "/api/2/configs", tok, map[string]any{"name": "race"}, "Idempotency-Key", `"same"`)
			if r.StatusCode != 201 {
				t.Errorf("request %d: %d %s", i, r.StatusCode, r.body)
			}
			bodies[i] = string(r.body)
		}()
	}
	wg.Wait()
	for i := 1; i < n; i++ {
		if bodies[i] != bodies[0] {
			t.Fatalf("different responses:\n%s\n%s", bodies[0], bodies[i])
		}
	}
	if c := countConfigs(t, e, alice.ID); c != 1 {
		t.Fatalf("%d configs created", c)
	}
}

// TestV2RetryAfterLostResponse: a PUT whose response was lost is retried
// with the same If-Match. Without the key it would now get 412; with it,
// the original success is replayed and no second revision appears.
func TestV2RetryAfterLostResponse(t *testing.T) {
	e := newEnv(t, nil)
	tok, _ := e.token(e.user("alice"))
	m, tag := e.createV2(tok, "a: 1")
	path := fmt.Sprintf("/api/2/configs/%d/content", m.ID)

	r1 := e.raw("PUT", path, tok, "application/yaml", "a: 2", "If-Match", tag, "Idempotency-Key", `"put-1"`)
	expect(t, r1, 200)
	r2 := e.raw("PUT", path, tok, "application/yaml", "a: 2", "If-Match", tag, "Idempotency-Key", `"put-1"`)
	if r2.StatusCode != 200 || r2.Header.Get("Idempotent-Replayed") != "true" || string(r2.body) != string(r1.body) {
		t.Fatalf("retry: %d %s", r2.StatusCode, r2.body)
	}
	expect(t, e.raw("PUT", path, tok, "application/yaml", "a: 2", "If-Match", tag), 412)
	var cur metaV2
	e.do("GET", fmt.Sprintf("/api/2/configs/%d", m.ID), tok, nil).json(t, &cur)
	if cur.Revision != 2 {
		t.Fatalf("revision %d", cur.Revision)
	}
}

func TestV2HistoryAndRestore(t *testing.T) {
	e := newEnv(t, nil)
	tok, _ := e.token(e.user("alice"))
	m, tag := e.createV2(tok, "v: 1")
	base := fmt.Sprintf("/api/2/configs/%d", m.ID)
	for _, c := range []string{"v: 2", "v: 3"} {
		r := e.raw("PUT", base+"/content", tok, "application/yaml", c, "If-Match", tag)
		expect(t, r, 200)
		tag = r.Header.Get("ETag")
	}

	r := e.do("GET", base+"/revisions", tok, nil)
	expect(t, r, 200)
	var revs []struct {
		Revision   int32   `json:"revision"`
		Current    bool    `json:"current"`
		DeviceName *string `json:"device_name"`
	}
	r.json(t, &revs)
	if len(revs) != 3 || revs[0].Revision != 3 || !revs[0].Current || revs[2].Current || revs[0].DeviceName == nil {
		t.Fatalf("revisions %+v", revs)
	}

	r = e.do("GET", base+"/revisions/1/content", tok, nil)
	if string(r.body) != "v: 1" || r.Header.Get("Repr-Digest") != digest("v: 1") || r.Header.Get("ETag") != `"r1"` {
		t.Fatalf("revision 1: %q %v", r.body, r.Header)
	}
	expect(t, e.do("GET", base+"/revisions/1/content", tok, nil, "If-None-Match", `"r1"`), 304)
	expect(t, e.do("GET", base+"/revisions/9/content", tok, nil), 404)

	expect(t, e.raw("POST", base+"/revisions/1/restore", tok, "application/json", "", "If-Match", `"v1"`), 412)
	r = e.raw("POST", base+"/revisions/1/restore", tok, "application/json", "", "If-Match", tag)
	expect(t, r, 200)
	var after metaV2
	r.json(t, &after)
	if after.Revision != 4 || after.ContentDigest != digest("v: 1") {
		t.Fatalf("after restore %+v", after)
	}
	expect(t, e.raw("POST", base+"/revisions/99/restore", tok, "application/json", "", "If-Match", r.Header.Get("ETag")), 404)
}

func TestV2PatchAndDelete(t *testing.T) {
	e := newEnv(t, nil)
	tok, _ := e.token(e.user("alice"))
	m, tag := e.createV2(tok, "a: 1")
	base := fmt.Sprintf("/api/2/configs/%d", m.ID)

	expect(t, e.do("PATCH", base, tok, map[string]any{"content": "a: 2"}, "If-Match", tag), 400)
	r := e.do("PATCH", base, tok, map[string]any{"name": "renamed"}, "If-Match", tag)
	expect(t, r, 200)
	var p metaV2
	r.json(t, &p)
	if p.Name != "renamed" || p.Revision != 1 || r.Header.Get("ETag") == tag {
		t.Fatalf("patch %+v", p)
	}
	expect(t, e.raw("DELETE", base, tok, "application/json", "", "If-Match", tag), 412)
	expect(t, e.raw("DELETE", base, tok, "application/json", "", "If-Match", r.Header.Get("ETag")), 204)
	expect(t, e.do("GET", base, tok, nil), 404)
}

func TestV2ObjectLevelAuthorization(t *testing.T) {
	e := newEnv(t, nil)
	alice, _ := e.token(e.user("alice"))
	bob, _ := e.token(e.user("bob"))
	m, tag := e.createV2(alice, "secret: 1")
	base := fmt.Sprintf("/api/2/configs/%d", m.ID)

	for _, c := range []struct{ method, path string }{
		{"GET", base}, {"GET", base + "/content"}, {"GET", base + "/revisions"},
		{"GET", base + "/revisions/1/content"},
	} {
		if r := e.do(c.method, c.path, bob, nil); r.StatusCode != 404 || strings.Contains(string(r.body), "secret") {
			t.Errorf("%s %s: %d", c.method, c.path, r.StatusCode)
		}
	}
	for _, c := range []struct{ method, path, ct, body string }{
		{"PUT", base + "/content", "application/yaml", "pwned: 1"},
		{"PATCH", base, "application/json", `{"name":"pwned"}`},
		{"DELETE", base, "application/json", ""},
		{"POST", base + "/revisions/1/restore", "application/json", ""},
	} {
		if r := e.raw(c.method, c.path, bob, c.ct, c.body, "If-Match", tag); r.StatusCode != 404 {
			t.Errorf("%s %s: %d", c.method, c.path, r.StatusCode)
		}
	}
	r := e.do("GET", "/api/2/configs", bob, nil)
	if strings.TrimSpace(string(r.body)) != "[]" {
		t.Fatalf("bob lists %s", r.body)
	}
	ro, _ := e.token(e.user("carol"), "configs:read")
	expect(t, e.raw("PUT", base+"/content", ro, "application/yaml", "a: 1", "If-Match", tag), 403)
}
