package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tabbysync/internal/auth"
	"tabbysync/internal/configs"
	"tabbysync/internal/store"
)

// API v1 mirrors Tabby Web's /api/1 so the desktop app's config sync works
// unchanged. Differences, all deliberate:
//   - the bearer token is accepted only in the Authorization header;
//   - config_sync_token is never returned (only its hash is stored) and is
//     read-only; tokens are managed per device with "syncd token";
//   - responses carry an ETag and writes honour If-Match;
//   - a write whose content equals the current content does not create a
//     revision or move modified_at, so other devices do not re-download.

type configJSON struct {
	ID                  int64   `json:"id"`
	User                int64   `json:"user"`
	Name                string  `json:"name"`
	Content             string  `json:"content"`
	LastUsedWithVersion *string `json:"last_used_with_version"`
	CreatedAt           string  `json:"created_at"`
	ModifiedAt          string  `json:"modified_at"`
}

// Same shape as Django REST Framework's datetime output.
func drfTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000Z") }

func toJSON(c configs.Config) configJSON {
	return configJSON{
		ID:                  c.ID,
		User:                c.UserID,
		Name:                c.Name,
		Content:             c.Content,
		LastUsedWithVersion: c.LastUsedWithVersion,
		CreatedAt:           drfTime(c.CreatedAt),
		ModifiedAt:          drfTime(c.ModifiedAt),
	}
}

// configBody accepts the writable fields plus the read-only ones a client
// may echo back, which are ignored as Tabby Web does.
type configBody struct {
	Name                optString       `json:"name"`
	Content             optString       `json:"content"`
	LastUsedWithVersion optNullString   `json:"last_used_with_version"`
	ID                  json.RawMessage `json:"id"`
	User                json.RawMessage `json:"user"`
	CreatedAt           json.RawMessage `json:"created_at"`
	ModifiedAt          json.RawMessage `json:"modified_at"`
}

func (b configBody) patch() configs.Patch {
	return configs.Patch{
		Name:                configs.Optional[string]{Set: b.Name.Set, Value: b.Name.Value},
		Content:             configs.Optional[string]{Set: b.Content.Set, Value: b.Content.Value},
		LastUsedWithVersion: configs.Optional[*string]{Set: b.LastUsedWithVersion.Set, Value: b.LastUsedWithVersion.Value},
	}
}

func (s *Server) routesV1(mux *http.ServeMux) {
	mux.Handle("GET /api/1/configs", s.authed(auth.ScopeConfigsRead, s.listConfigs))
	mux.Handle("POST /api/1/configs", s.authed(auth.ScopeConfigsWrite, s.createConfig))
	mux.Handle("GET /api/1/configs/{id}", s.authed(auth.ScopeConfigsRead, s.getConfig))
	mux.Handle("PATCH /api/1/configs/{id}", s.authed(auth.ScopeConfigsWrite, s.updateConfig))
	mux.Handle("PUT /api/1/configs/{id}", s.authed(auth.ScopeConfigsWrite, s.updateConfig))
	mux.Handle("DELETE /api/1/configs/{id}", s.authed(auth.ScopeConfigsWrite, s.deleteConfig))
	mux.Handle("GET /api/1/user", s.authed(auth.ScopeUserRead, s.getUser))
	mux.Handle("PUT /api/1/user", s.authed(auth.ScopeUserWrite, s.updateUser))
	mux.Handle("PATCH /api/1/user", s.authed(auth.ScopeUserWrite, s.updateUser))
}

func (s *Server) listConfigs(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	list, err := s.configs.List(r.Context(), a)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]configJSON, len(list))
	for i, c := range list {
		out[i] = toJSON(c)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createConfig(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	var body configBody
	if err := decodeJSON(w, r, s.bodyLimit(), &body); err != nil {
		s.writeError(w, r, err)
		return
	}
	c, err := s.configs.Create(r.Context(), a, body.patch())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(c.Version))
	w.Header().Set("Location", "/api/1/configs/"+strconv.FormatInt(c.ID, 10))
	writeJSON(w, http.StatusCreated, toJSON(c))
}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	id, ok := pathID(r)
	if !ok {
		s.writeError(w, r, configs.ErrNotFound)
		return
	}
	c, err := s.configs.Get(r.Context(), a, id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(c.Version))
	writeJSON(w, http.StatusOK, toJSON(c))
}

func (s *Server) updateConfig(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	id, ok := pathID(r)
	if !ok {
		s.writeError(w, r, configs.ErrNotFound)
		return
	}
	ifVersion, err := parseIfMatch(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var body configBody
	if err := decodeJSON(w, r, s.bodyLimit(), &body); err != nil {
		s.writeError(w, r, err)
		return
	}
	p := body.patch()
	p.IfVersion = ifVersion
	c, err := s.configs.Update(r.Context(), a, id, p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(c.Version))
	writeJSON(w, http.StatusOK, toJSON(c))
}

func (s *Server) deleteConfig(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	id, ok := pathID(r)
	if !ok {
		s.writeError(w, r, configs.ErrNotFound)
		return
	}
	if err := s.configs.Delete(r.Context(), a, id); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type userJSON struct {
	ID                           int64   `json:"id"`
	Username                     string  `json:"username"`
	ActiveConfig                 *int64  `json:"active_config"`
	CustomConnectionGateway      *string `json:"custom_connection_gateway"`
	CustomConnectionGatewayToken *string `json:"custom_connection_gateway_token"`
	ConfigSyncToken              *string `json:"config_sync_token"`
	IsPro                        bool    `json:"is_pro"`
	IsSponsor                    bool    `json:"is_sponsor"`
	GithubUsername               *string `json:"github_username"`
}

type userBody struct {
	ActiveConfig optNullInt `json:"active_config"`
	// Read-only or unsupported; accepted and ignored so that a client
	// echoing the whole object back does not fail.
	ID                           json.RawMessage `json:"id"`
	Username                     json.RawMessage `json:"username"`
	CustomConnectionGateway      json.RawMessage `json:"custom_connection_gateway"`
	CustomConnectionGatewayToken json.RawMessage `json:"custom_connection_gateway_token"`
	ConfigSyncToken              json.RawMessage `json:"config_sync_token"`
	IsPro                        json.RawMessage `json:"is_pro"`
	IsSponsor                    json.RawMessage `json:"is_sponsor"`
	GithubUsername               json.RawMessage `json:"github_username"`
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	u, err := s.db.GetUser(r.Context(), a.UserID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, userToJSON(u))
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, a auth.Actor) {
	var body userBody
	if err := decodeJSON(w, r, 64<<10, &body); err != nil {
		s.writeError(w, r, err)
		return
	}
	if body.ActiveConfig.Set {
		err := s.db.SetActiveConfig(r.Context(), a.UserID, body.ActiveConfig.Value)
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, r, &configs.ValidationError{Field: "active_config", Reason: "no such config"})
			return
		}
		if err != nil {
			s.writeError(w, r, err)
			return
		}
	}
	s.getUser(w, r, a)
}

func userToJSON(u store.User) userJSON {
	return userJSON{ID: u.ID, Username: u.Username, ActiveConfig: u.ActiveConfigID, IsPro: true}
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// parseIfMatch accepts a single strong ETag of the form "v<version>". "*"
// (any current representation) is the same as no condition here, because
// the handler fails with 404 if the config does not exist.
func parseIfMatch(r *http.Request) (configs.Optional[int64], error) {
	v := strings.TrimSpace(r.Header.Get("If-Match"))
	if v == "" || v == "*" {
		return configs.Optional[int64]{}, nil
	}
	if !strings.HasPrefix(v, `"v`) || !strings.HasSuffix(v, `"`) || len(v) < 4 {
		return configs.Optional[int64]{}, &bodyError{http.StatusBadRequest, `If-Match must be a single ETag like "v12".`}
	}
	n, err := strconv.ParseInt(v[2:len(v)-1], 10, 64)
	if err != nil || n < 1 {
		return configs.Optional[int64]{}, &bodyError{http.StatusBadRequest, `If-Match must be a single ETag like "v12".`}
	}
	return configs.Some(n), nil
}
