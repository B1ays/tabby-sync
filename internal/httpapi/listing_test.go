package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"tabbysync/internal/auth"
	"tabbysync/internal/configs"
)

func actorOf(userID int64) auth.Actor { return auth.Actor{UserID: userID} }

// TestConfigListings: the v1 list still carries every config's content,
// the v2 list and the web page do not decrypt anything.
func TestConfigListings(t *testing.T) {
	e := newEnv(t, nil)
	alice := e.user("alice")
	tok, _ := e.token(alice)
	ctx := context.Background()
	var ids []int64
	for i := range 3 {
		c, err := e.svc.Create(ctx, actorOf(alice.ID), configs.Patch{Content: configs.Some(fmt.Sprintf("n: %d%s", i, strings.Repeat("x", i)))})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, c.ID)
	}

	r := e.do("GET", "/api/1/configs", tok, nil)
	expect(t, r, 200)
	var v1 []cfgJSON
	r.json(t, &v1)
	if len(v1) != 3 || v1[0].ID != ids[0] || v1[2].Content != "n: 2xx" {
		t.Fatalf("v1 list %+v", v1)
	}

	r = e.do("GET", "/api/2/configs", tok, nil)
	expect(t, r, 200)
	var v2 []map[string]any
	r.json(t, &v2)
	if len(v2) != 3 || v2[2]["size"] != float64(len("n: 2xx")) {
		t.Fatalf("v2 list %+v", v2)
	}
	if _, ok := v2[0]["content_digest"]; ok {
		t.Fatal("v2 list must not compute digests")
	}
	var one metaV2
	e.do("GET", fmt.Sprintf("/api/2/configs/%d", ids[2]), tok, nil).json(t, &one)
	if one.ContentDigest != digest("n: 2xx") || one.Size != 6 {
		t.Fatalf("single meta %+v", one)
	}

	// Break the last config's ciphertext. The v2 list does not decrypt and
	// still works; the v1 list streams the first two and then cuts the
	// connection instead of sending a short list that looks complete.
	pool := rawPool(t, e)
	var ct, dek []byte
	var kek string
	if err := pool.QueryRow(ctx, `SELECT ciphertext, dek_wrapped, kek_id FROM config_revisions WHERE config_id = $1`, ids[0]).
		Scan(&ct, &dek, &kek); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM config_revisions WHERE config_id = $1`, ids[2]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO config_revisions (config_id, user_id, revision, ciphertext, dek_wrapped, kek_id, size)
		VALUES ($1, $2, 1, $3, $4, $5, 6)`, ids[2], alice.ID, ct, dek, kek); err != nil {
		t.Fatal(err)
	}
	expect(t, e.do("GET", "/api/2/configs", tok, nil), 200)
	// Small responses are still buffered when the handler aborts, so the
	// client may see EOF before the headers; larger ones arrive truncated.
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/1/configs", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := e.srv.Client().Do(req)
	if err == nil {
		body, rerr := io.ReadAll(res.Body)
		res.Body.Close()
		if rerr == nil && json.Valid(body) {
			t.Fatalf("v1 list after a decryption failure looks complete: %d %q", res.StatusCode, body)
		}
	}
}
