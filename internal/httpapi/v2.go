package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tabbysync/internal/auth"
	"tabbysync/internal/configs"
	"tabbysync/internal/store"
)

// API v2 is for clients that can handle conflicts:
//   - every change needs If-Match with the current ETag (428 without it,
//     412 when stale), so concurrent edits are never silently overwritten;
//   - content lives at its own URL as raw YAML, with Repr-Digest on
//     responses and optional Content-Digest verification on uploads;
//   - unsafe requests accept Idempotency-Key (required for POST), so a
//     retry after a lost response replays the original outcome;
//   - history can be listed, read and restored.

const idempotencyTTL = 24 * time.Hour

type configMetaV2 struct {
	ID                  int64     `json:"id"`
	Name                string    `json:"name"`
	Version             int64     `json:"version"`
	Revision            int32     `json:"revision"`
	Size                int       `json:"size"`
	ContentDigest       string    `json:"content_digest"`
	LastUsedWithVersion *string   `json:"last_used_with_version"`
	CreatedAt           time.Time `json:"created_at"`
	ModifiedAt          time.Time `json:"modified_at"`
}

func metaV2(c configs.Config) configMetaV2 {
	return configMetaV2{
		ID: c.ID, Name: c.Name, Version: c.Version, Revision: c.Revision,
		Size: len(c.Content), ContentDigest: reprDigest([]byte(c.Content)),
		LastUsedWithVersion: c.LastUsedWithVersion, CreatedAt: c.CreatedAt, ModifiedAt: c.ModifiedAt,
	}
}

type revisionV2 struct {
	Revision   int32     `json:"revision"`
	Size       int32     `json:"size"`
	CreatedAt  time.Time `json:"created_at"`
	DeviceName *string   `json:"device_name"`
	Current    bool      `json:"current"`
}

func (s *Server) routesV2(mux *http.ServeMux) {
	r, w := auth.ScopeConfigsRead, auth.ScopeConfigsWrite
	mux.Handle("GET /api/2/configs", s.authed(r, s.listConfigsV2))
	mux.Handle("POST /api/2/configs", s.authed(w, s.createConfigV2))
	mux.Handle("GET /api/2/configs/{id}", s.authed(r, s.getConfigV2))
	mux.Handle("PATCH /api/2/configs/{id}", s.authed(w, s.patchConfigV2))
	mux.Handle("DELETE /api/2/configs/{id}", s.authed(w, s.deleteConfigV2))
	mux.Handle("GET /api/2/configs/{id}/content", s.authed(r, s.getContentV2))
	mux.Handle("PUT /api/2/configs/{id}/content", s.authed(w, s.putContentV2))
	mux.Handle("GET /api/2/configs/{id}/revisions", s.authed(r, s.listRevisionsV2))
	mux.Handle("GET /api/2/configs/{id}/revisions/{rev}/content", s.authed(r, s.getRevisionContentV2))
	mux.Handle("POST /api/2/configs/{id}/revisions/{rev}/restore", s.authed(w, s.restoreV2))
}

func (s *Server) listConfigsV2(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	list, err := s.configs.List(r.Context(), a)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]configMetaV2, len(list))
	for i, c := range list {
		out[i] = metaV2(c)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getConfigV2(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	c, ok := s.loadV2(w, r, a)
	if !ok {
		return
	}
	w.Header().Set("ETag", etag(c.Version))
	writeJSON(w, http.StatusOK, metaV2(c))
}

func (s *Server) getContentV2(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	c, ok := s.loadV2(w, r, a)
	if !ok {
		return
	}
	tag := etag(c.Version)
	w.Header().Set("ETag", tag)
	if noneMatch(r, tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeContent(w, []byte(c.Content))
}

func (s *Server) loadV2(w http.ResponseWriter, r *http.Request, a auth.Actor) (configs.Config, bool) {
	id, ok := pathID(r)
	if !ok {
		s.writeError(w, r, configs.ErrNotFound)
		return configs.Config{}, false
	}
	c, err := s.configs.Get(r.Context(), a, id)
	if err != nil {
		s.writeError(w, r, err)
		return configs.Config{}, false
	}
	return c, true
}

func writeContent(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Repr-Digest", reprDigest(b))
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	// Served as YAML with nosniff and CSP default-src 'none': a browser
	// will not render it as HTML.
	_, _ = w.Write(b) //nolint:gosec // see above
}

func (s *Server) listRevisionsV2(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	c, ok := s.loadV2(w, r, a)
	if !ok {
		return
	}
	revs, err := s.configs.Revisions(r.Context(), a, c.ID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]revisionV2, len(revs))
	for i, rv := range revs {
		out[i] = revisionV2{Revision: rv.Revision, Size: rv.Size, CreatedAt: rv.CreatedAt,
			DeviceName: rv.DeviceName, Current: rv.Revision == c.Revision}
	}
	w.Header().Set("ETag", etag(c.Version))
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getRevisionContentV2(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	id, ok1 := pathID(r)
	rev, ok2 := pathRev(r)
	if !ok1 || !ok2 {
		s.writeError(w, r, configs.ErrNotFound)
		return
	}
	content, err := s.configs.RevisionContent(r.Context(), a, id, rev)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	// A revision never changes, so its tag is stable.
	tag := fmt.Sprintf(`"r%d"`, rev)
	w.Header().Set("ETag", tag)
	if noneMatch(r, tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeContent(w, []byte(content))
}

type createBodyV2 struct {
	Name                optString     `json:"name"`
	Content             optString     `json:"content"`
	LastUsedWithVersion optNullString `json:"last_used_with_version"`
}

func (s *Server) createConfigV2(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	body, err := readBody(w, r, s.bodyLimit(), "application/json")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var b createBodyV2
	if err := decodeStrict(body, &b); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.mutate(w, r, a, true, body, func(ctx context.Context, q *store.Queries, out http.ResponseWriter) error {
		c, err := s.configs.CreateTx(ctx, q, a, configs.Patch{
			Name:                configs.Optional[string]{Set: b.Name.Set, Value: b.Name.Value},
			Content:             configs.Optional[string]{Set: b.Content.Set, Value: b.Content.Value},
			LastUsedWithVersion: configs.Optional[*string]{Set: b.LastUsedWithVersion.Set, Value: b.LastUsedWithVersion.Value},
		})
		if err != nil {
			return err
		}
		out.Header().Set("ETag", etag(c.Version))
		out.Header().Set("Location", "/api/2/configs/"+strconv.FormatInt(c.ID, 10))
		writeJSON(out, http.StatusCreated, metaV2(c))
		return nil
	})
}

type patchBodyV2 struct {
	Name                optString     `json:"name"`
	LastUsedWithVersion optNullString `json:"last_used_with_version"`
}

func (s *Server) patchConfigV2(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	id, version, ok := s.preconditions(w, r)
	if !ok {
		return
	}
	body, err := readBody(w, r, 64<<10, "application/json")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var b patchBodyV2
	if err := decodeStrict(body, &b); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.mutate(w, r, a, false, body, func(ctx context.Context, q *store.Queries, out http.ResponseWriter) error {
		c, err := s.configs.UpdateTx(ctx, q, a, id, configs.Patch{
			Name:                configs.Optional[string]{Set: b.Name.Set, Value: b.Name.Value},
			LastUsedWithVersion: configs.Optional[*string]{Set: b.LastUsedWithVersion.Set, Value: b.LastUsedWithVersion.Value},
			IfVersion:           configs.Some(version),
		})
		if err != nil {
			return err
		}
		out.Header().Set("ETag", etag(c.Version))
		writeJSON(out, http.StatusOK, metaV2(c))
		return nil
	})
}

func (s *Server) deleteConfigV2(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	id, version, ok := s.preconditions(w, r)
	if !ok {
		return
	}
	s.mutate(w, r, a, false, nil, func(ctx context.Context, q *store.Queries, out http.ResponseWriter) error {
		if err := s.configs.DeleteTx(ctx, q, a, id, configs.Some(version)); err != nil {
			return err
		}
		out.WriteHeader(http.StatusNoContent)
		return nil
	})
}

func (s *Server) putContentV2(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	id, version, ok := s.preconditions(w, r)
	if !ok {
		return
	}
	if ce := r.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
		writeProblem(w, r, http.StatusUnsupportedMediaType, "Content-Encoding is not supported.")
		return
	}
	body, err := readBody(w, r, int64(s.cfg.Limits.MaxConfigBytes),
		"application/yaml", "application/x-yaml", "text/yaml", "application/json", "text/plain")
	if err == nil {
		err = checkRequestDigest(r, body)
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.mutate(w, r, a, false, body, func(ctx context.Context, q *store.Queries, out http.ResponseWriter) error {
		c, err := s.configs.UpdateTx(ctx, q, a, id, configs.Patch{
			Content:   configs.Some(string(body)),
			IfVersion: configs.Some(version),
		})
		if err != nil {
			return err
		}
		out.Header().Set("ETag", etag(c.Version))
		out.Header().Set("Repr-Digest", reprDigest([]byte(c.Content)))
		writeJSON(out, http.StatusOK, metaV2(c))
		return nil
	})
}

func (s *Server) restoreV2(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	id, version, ok := s.preconditions(w, r)
	if !ok {
		return
	}
	rev, ok := pathRev(r)
	if !ok {
		s.writeError(w, r, configs.ErrNotFound)
		return
	}
	s.mutate(w, r, a, false, nil, func(ctx context.Context, q *store.Queries, out http.ResponseWriter) error {
		c, err := s.configs.RestoreTx(ctx, q, a, id, rev, version)
		if err != nil {
			return err
		}
		out.Header().Set("ETag", etag(c.Version))
		writeJSON(out, http.StatusOK, metaV2(c))
		return nil
	})
}

// preconditions extracts the config ID and the mandatory If-Match.
func (s *Server) preconditions(w http.ResponseWriter, r *http.Request) (int64, int64, bool) {
	id, ok := pathID(r)
	if !ok {
		s.writeError(w, r, configs.ErrNotFound)
		return 0, 0, false
	}
	v := strings.TrimSpace(r.Header.Get("If-Match"))
	if v == "" {
		writeProblem(w, r, http.StatusPreconditionRequired,
			"If-Match with the current ETag is required; read the config first.")
		return 0, 0, false
	}
	if v == "*" {
		s.writeError(w, r, &bodyError{http.StatusBadRequest, `If-Match "*" is not accepted; send the current ETag.`})
		return 0, 0, false
	}
	ver, err := parseIfMatch(r)
	if err != nil {
		s.writeError(w, r, err)
		return 0, 0, false
	}
	return id, ver.Value, true
}

// noneMatch implements If-None-Match for GET (weak comparison).
func noneMatch(r *http.Request, tag string) bool {
	for _, v := range strings.Split(r.Header.Get("If-None-Match"), ",") {
		v = strings.TrimPrefix(strings.TrimSpace(v), "W/")
		if v == "*" || v == tag {
			return true
		}
	}
	return false
}

func readBody(w http.ResponseWriter, r *http.Request, limit int64, types ...string) ([]byte, error) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !contains(types, mt) {
		return nil, &bodyError{http.StatusUnsupportedMediaType, "Content-Type must be one of " + strings.Join(types, ", ") + "."}
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return nil, &bodyError{http.StatusRequestEntityTooLarge, fmt.Sprintf("Request body exceeds %d bytes.", limit)}
	}
	return b, err
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func decodeStrict(body []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var ne *nullError
		if errors.As(err, &ne) {
			return &bodyError{http.StatusBadRequest, "Field may not be null."}
		}
		if msg := err.Error(); strings.HasPrefix(msg, "json: unknown field ") {
			return &bodyError{http.StatusBadRequest, "Unknown field " + strings.TrimPrefix(msg, "json: unknown field ") + "."}
		}
		return &bodyError{http.StatusBadRequest, "Malformed JSON body."}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return &bodyError{http.StatusBadRequest, "Body must contain a single JSON object."}
	}
	return nil
}

// captured buffers a response so it can be stored for idempotent replay
// and discarded if the transaction is rolled back.
type captured struct {
	status int
	header http.Header
	body   bytes.Buffer
}

func newCaptured() *captured { return &captured{header: http.Header{}} }

func (c *captured) Header() http.Header { return c.header }
func (c *captured) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
}
func (c *captured) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return c.body.Write(b)
}

// replayHeaders are the response headers kept with an idempotent result.
var replayHeaders = []string{"Content-Type", "ETag", "Location", "Repr-Digest"}

func (c *captured) stored(fp []byte) store.StoredResponse {
	h := map[string]string{}
	for _, k := range replayHeaders {
		if v := c.header.Get(k); v != "" {
			h[k] = v
		}
	}
	return store.StoredResponse{Fingerprint: fp, Status: c.status, Headers: h, Body: c.body.Bytes()}
}

func writeStored(w http.ResponseWriter, sr store.StoredResponse) {
	for k, v := range sr.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(sr.Status)
	_, _ = w.Write(sr.Body)
}

var errRollback = errors.New("rollback")

// mutate runs op in a transaction, honouring Idempotency-Key. The key's
// record is written in the same transaction as op's changes. Client errors
// (4xx) are recorded too, so a retry gets the same answer; server errors
// roll everything back and leave the key free for a retry.
func (s *Server) mutate(w http.ResponseWriter, r *http.Request, a auth.Actor, keyRequired bool, body []byte,
	op func(ctx context.Context, q *store.Queries, out http.ResponseWriter) error) {
	key, err := idempotencyKey(r)
	if err == nil && key == "" && keyRequired {
		err = &bodyError{http.StatusBadRequest, "Idempotency-Key header is required."}
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	fp := fingerprint(r, body)
	ctx := r.Context()
	res := newCaptured()
	var replay *store.StoredResponse

	err = s.db.InTx(ctx, func(q *store.Queries) error {
		if key != "" {
			prev, err := q.ClaimIdempotencyKey(ctx, a.UserID, key, fp, idempotencyTTL)
			if err != nil {
				return err
			}
			if prev != nil {
				replay = prev
				return nil
			}
		}
		if err := q.Savepoint(ctx, func(sq *store.Queries) error { return op(ctx, sq, res) }); err != nil {
			res = newCaptured()
			s.writeError(res, r, err)
		}
		if res.status >= 500 {
			return errRollback
		}
		if key != "" {
			return q.CompleteIdempotencyKey(ctx, a.UserID, key, res.stored(fp))
		}
		return nil
	})
	switch {
	case errors.Is(err, errRollback):
		writeStored(w, res.stored(nil))
	case err != nil:
		s.writeError(w, r, err)
	case replay != nil && !bytes.Equal(replay.Fingerprint, fp):
		writeProblem(w, r, http.StatusUnprocessableEntity,
			"This Idempotency-Key was already used for a different request.")
	case replay != nil:
		w.Header().Set("Idempotent-Replayed", "true")
		writeStored(w, *replay)
	default:
		writeStored(w, res.stored(nil))
	}
}

// idempotencyKey reads the header as a structured-field string
// ("value") or a bare token, 1 to 255 visible ASCII characters.
func idempotencyKey(r *http.Request) (string, error) {
	v := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if v == "" {
		return "", nil
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	if len(v) == 0 || len(v) > 255 {
		return "", &bodyError{http.StatusBadRequest, "Idempotency-Key must be 1 to 255 characters."}
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e || v[i] == '"' || v[i] == '\\' {
			return "", &bodyError{http.StatusBadRequest, "Idempotency-Key contains invalid characters."}
		}
	}
	return v, nil
}

// fingerprint identifies the request a key was first used for.
func fingerprint(r *http.Request, body []byte) []byte {
	h := sha256.New()
	for _, part := range []string{r.Method, r.URL.Path, strings.TrimSpace(r.Header.Get("If-Match"))} {
		_ = binary.Write(h, binary.BigEndian, uint32(len(part)))
		h.Write([]byte(part))
	}
	h.Write(body)
	return h.Sum(nil)
}
