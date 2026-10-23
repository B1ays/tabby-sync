package httpapi_test

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"tabbysync/internal/auth"
	"tabbysync/internal/config"
)

// The OpenAPI document must describe the server as it is: the same routes,
// the status codes the handlers really return, and the JSON fields they
// really send. These tests fail when one changes without the other.

const specPath = "../../docs/openapi.yaml"

type spec map[string]any

func loadSpec(t *testing.T) spec {
	t.Helper()
	b, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	// Decode into a plain map: decoding into the named type would make every
	// nested mapping a spec as well.
	var raw map[string]any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	return spec(raw)
}

func (s spec) m(v any) map[string]any {
	out, _ := v.(map[string]any)
	return out
}

// resolve follows a {$ref: '#/components/...'} if there is one.
func (s spec) resolve(v any) map[string]any {
	node := s.m(v)
	ref, ok := node["$ref"].(string)
	if !ok {
		return node
	}
	cur := map[string]any(s)
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		cur = s.m(cur[part])
	}
	return cur
}

func (s spec) operation(method, path string) map[string]any {
	return s.m(s.m(s.m(s["paths"])[path])[strings.ToLower(method)])
}

var routeRe = regexp.MustCompile(`mux\.Handle(?:Func)?\("([A-Z]+) (/(?:api/|healthz|readyz)[^"]*)"`)

func TestOpenAPIRoutesMatchCode(t *testing.T) {
	s := loadSpec(t)
	var inCode, inSpec []string
	for _, f := range []string{"v1.go", "v2.go", "server.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range routeRe.FindAllStringSubmatch(string(src), -1) {
			inCode = append(inCode, m[1]+" "+m[2])
		}
	}
	for path, item := range s.m(s["paths"]) {
		for method := range s.m(item) {
			switch method {
			case "get", "post", "put", "patch", "delete":
				inSpec = append(inSpec, strings.ToUpper(method)+" "+path)
			}
		}
	}
	sort.Strings(inCode)
	sort.Strings(inSpec)
	if len(inCode) < 20 {
		t.Fatalf("found only %d routes in code; has the registration pattern changed?", len(inCode))
	}
	for _, r := range inCode {
		if !slices.Contains(inSpec, r) {
			t.Errorf("route %s is not in %s", r, specPath)
		}
	}
	for _, r := range inSpec {
		if !slices.Contains(inCode, r) {
			t.Errorf("%s documents %s, which the server does not have", specPath, r)
		}
	}
}

// fields returns the properties and required fields of a schema, merging allOf.
func (s spec) fields(schema map[string]any) (props, required []string) {
	schema = s.resolve(schema)
	for _, part := range s.listOf(schema["allOf"]) {
		p, r := s.fields(s.m(part))
		props = append(props, p...)
		required = append(required, r...)
	}
	for k := range s.m(schema["properties"]) {
		props = append(props, k)
	}
	for _, r := range s.listOf(schema["required"]) {
		required = append(required, r.(string))
	}
	return props, required
}

func (s spec) listOf(v any) []any {
	l, _ := v.([]any)
	return l
}

// check asserts that status is documented for the operation and, for JSON
// bodies, that every object has exactly documented fields and all required ones.
func (s spec) check(t *testing.T, method, path string, r resp) {
	t.Helper()
	op := s.operation(method, path)
	if op == nil {
		t.Fatalf("%s %s: no such operation in the spec", method, path)
	}
	res := s.resolve(s.m(op["responses"])[strconv.Itoa(r.StatusCode)])
	if res == nil {
		t.Errorf("%s %s returned %d, which the spec does not document", method, path, r.StatusCode)
		return
	}
	ct := strings.Split(r.Header.Get("Content-Type"), ";")[0]
	media := s.m(s.m(res["content"])[ct])
	if len(r.body) == 0 || !strings.Contains(ct, "json") {
		if len(r.body) > 0 && media == nil {
			t.Errorf("%s %s %d: content type %q is not documented", method, path, r.StatusCode, ct)
		}
		return
	}
	if media == nil {
		t.Errorf("%s %s %d: content type %q is not documented", method, path, r.StatusCode, ct)
		return
	}
	schema := s.resolve(media["schema"])
	var body any
	if err := json.Unmarshal(r.body, &body); err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	objects := []any{body}
	if schema["type"] == "array" {
		objects, _ = body.([]any)
		schema = s.resolve(schema["items"])
	}
	props, required := s.fields(schema)
	for _, o := range objects {
		obj, ok := o.(map[string]any)
		if !ok {
			t.Errorf("%s %s: expected an object, got %T", method, path, o)
			continue
		}
		for k := range obj {
			if !slices.Contains(props, k) {
				t.Errorf("%s %s %d: field %q is not in the schema", method, path, r.StatusCode, k)
			}
		}
		for _, k := range required {
			if _, ok := obj[k]; !ok {
				t.Errorf("%s %s %d: required field %q is missing", method, path, r.StatusCode, k)
			}
		}
	}
}

// TestOpenAPIMatchesResponses drives every operation through its main
// success and error paths and checks each response against the spec.
func TestOpenAPIMatchesResponses(t *testing.T) {
	s := loadSpec(t)
	e := newEnv(t, func(c *config.Config) { c.Limits.MaxConfigsPerUser = 3 })
	e.svc.Limits.MaxConfigsPerUser = 3
	alice := e.user("alice")
	tok, _ := e.token(alice)
	ro, _ := e.token(alice, auth.ScopeConfigsRead)

	const (
		v1List, v1One, v1User = "/api/1/configs", "/api/1/configs/{id}", "/api/1/user"
		v2List, v2One         = "/api/2/configs", "/api/2/configs/{id}"
		v2Content, v2Revs     = "/api/2/configs/{id}/content", "/api/2/configs/{id}/revisions"
		v2RevContent          = "/api/2/configs/{id}/revisions/{rev}/content"
		v2Restore             = "/api/2/configs/{id}/revisions/{rev}/restore"
	)

	// API v1.
	r := e.do("POST", v1List, tok, map[string]any{"name": "a"})
	s.check(t, "POST", v1List, r)
	var c cfgJSON
	r.json(t, &c)
	one := fmt.Sprintf("/api/1/configs/%d", c.ID)
	s.check(t, "GET", v1List, e.do("GET", v1List, tok, nil))
	s.check(t, "GET", v1One, e.do("GET", one, tok, nil))
	s.check(t, "GET", v1One, e.do("GET", "/api/1/configs/999999", tok, nil))
	s.check(t, "PATCH", v1One, e.do("PATCH", one, tok, map[string]any{"content": "a: 1"}))
	s.check(t, "PATCH", v1One, e.do("PATCH", one, tok, map[string]any{"content": "a: 2"}, "If-Match", `"v99"`))
	s.check(t, "PATCH", v1One, e.do("PATCH", one, tok, map[string]any{"content": "[1]"}))
	s.check(t, "PUT", v1One, e.do("PUT", one, tok, map[string]any{"name": "b"}))
	s.check(t, "POST", v1List, e.raw("POST", v1List, tok, "text/plain", "{}"))
	s.check(t, "POST", v1List, e.do("POST", v1List, ro, map[string]any{}))
	s.check(t, "GET", v1List, e.do("GET", v1List, "", nil))
	s.check(t, "GET", v1User, e.do("GET", v1User, tok, nil))
	s.check(t, "PUT", v1User, e.do("PUT", v1User, tok, map[string]any{"active_config": c.ID}))
	s.check(t, "PATCH", v1User, e.do("PATCH", v1User, tok, map[string]any{"active_config": 999999}))

	// API v2.
	r = e.do("POST", v2List, tok, map[string]any{"name": "x", "content": "v: 1"}, "Idempotency-Key", `"k1"`)
	s.check(t, "POST", v2List, r)
	var m metaV2
	r.json(t, &m)
	tag := r.Header.Get("ETag")
	s.check(t, "POST", v2List, e.do("POST", v2List, tok, map[string]any{"name": "x", "content": "v: 1"}, "Idempotency-Key", `"k1"`))
	s.check(t, "POST", v2List, e.do("POST", v2List, tok, map[string]any{"name": "y"}, "Idempotency-Key", `"k1"`))
	s.check(t, "POST", v2List, e.do("POST", v2List, tok, map[string]any{"name": "z"}))
	s.check(t, "POST", v2List, e.do("POST", v2List, tok, map[string]any{}, "Idempotency-Key", `"k2"`))
	s.check(t, "GET", v2List, e.do("GET", v2List, tok, nil))

	id := strconv.FormatInt(m.ID, 10)
	path := func(p string) string { return strings.ReplaceAll(strings.ReplaceAll(p, "{id}", id), "{rev}", "1") }
	s.check(t, "GET", v2One, e.do("GET", path(v2One), tok, nil))
	s.check(t, "GET", v2Content, e.do("GET", path(v2Content), tok, nil))
	s.check(t, "GET", v2Content, e.do("GET", path(v2Content), tok, nil, "If-None-Match", tag))
	s.check(t, "PUT", v2Content, e.raw("PUT", path(v2Content), tok, "application/yaml", "v: 2"))
	s.check(t, "PUT", v2Content, e.raw("PUT", path(v2Content), tok, "application/yaml", "v: 2", "If-Match", "*"))
	s.check(t, "PUT", v2Content, e.raw("PUT", path(v2Content), tok, "application/yaml", "v: 2", "If-Match", tag,
		"Content-Digest", digest("other")))
	s.check(t, "PUT", v2Content, e.raw("PUT", path(v2Content), tok, "image/png", "v: 2", "If-Match", tag))
	r = e.raw("PUT", path(v2Content), tok, "application/yaml", "v: 2", "If-Match", tag)
	s.check(t, "PUT", v2Content, r)
	tag = r.Header.Get("ETag")
	s.check(t, "PATCH", v2One, e.do("PATCH", path(v2One), tok, map[string]any{"name": "renamed"}, "If-Match", `"v1"`))
	r = e.do("PATCH", path(v2One), tok, map[string]any{"name": "renamed"}, "If-Match", tag)
	s.check(t, "PATCH", v2One, r)
	tag = r.Header.Get("ETag")
	s.check(t, "GET", v2Revs, e.do("GET", path(v2Revs), tok, nil))
	s.check(t, "GET", v2RevContent, e.do("GET", path(v2RevContent), tok, nil))
	s.check(t, "GET", v2RevContent, e.do("GET", path(v2RevContent), tok, nil, "If-None-Match", `"r1"`))
	s.check(t, "GET", v2RevContent, e.do("GET", strings.Replace(path(v2RevContent), "/1/", "/99/", 1), tok, nil))
	s.check(t, "POST", v2Restore, e.raw("POST", path(v2Restore), tok, "application/json", ""))
	r = e.raw("POST", path(v2Restore), tok, "application/json", "", "If-Match", tag)
	s.check(t, "POST", v2Restore, r)
	tag = r.Header.Get("ETag")
	s.check(t, "DELETE", v2One, e.raw("DELETE", path(v2One), tok, "application/json", "", "If-Match", `"v1"`))
	s.check(t, "DELETE", v2One, e.raw("DELETE", path(v2One), tok, "application/json", "", "If-Match", tag))
	s.check(t, "DELETE", v1One, e.do("DELETE", one, tok, nil))

	// Health.
	s.check(t, "GET", "/healthz", e.do("GET", "/healthz", "", nil))
	s.check(t, "GET", "/readyz", e.do("GET", "/readyz", "", nil))
}
