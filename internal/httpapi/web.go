package httpapi

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"tabbysync/internal/auth"
	"tabbysync/internal/configs"
	"tabbysync/internal/store"
)

//go:embed web/*.html web/style.css
var webFS embed.FS

// The pages need no scripts; styles come only from our own stylesheet.
const webCSP = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'"

var pageNames = []string{"login", "error", "reauth", "configs", "config", "revision", "devices", "token"}

func loadTemplates() map[string]*template.Template {
	funcs := template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05") },
		"fmtTimePtr": func(t *time.Time) string {
			if t == nil {
				return "—"
			}
			return t.Local().Format("2006-01-02 15:04:05")
		},
		"expired": func(t *time.Time) bool { return t != nil && !time.Now().Before(*t) },
		"join":    strings.Join,
		"deref": func(p *int64) int64 {
			if p == nil {
				return 0
			}
			return *p
		},
		"size": func(n any) string {
			var v int64
			switch x := n.(type) {
			case int:
				v = int64(x)
			case int32:
				v = int64(x)
			}
			if v < 1024 {
				return fmt.Sprintf("%d Б", v)
			}
			return fmt.Sprintf("%.1f КБ", float64(v)/1024)
		},
	}
	base := template.Must(template.New("").Funcs(funcs).ParseFS(webFS, "web/*.html"))
	out := map[string]*template.Template{}
	for _, name := range pageNames {
		t := template.Must(base.Clone())
		template.Must(t.New("content").Parse(`{{template "` + name + `" .}}`))
		out[name] = t
	}
	return out
}

type page struct {
	Title   string
	Session *webSession
	CSRF    string
	Flash   string
	Data    any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	if p.Session != nil {
		p.CSRF = p.Session.csrfToken()
	}
	var buf bytes.Buffer
	if err := s.tmpl[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		s.log.ErrorContext(r.Context(), "render", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", webCSP)
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if msg == "" {
		msg = "Что-то пошло не так. Код запроса: " + requestIDFrom(r.Context())
	}
	s.render(w, r, status, "error", page{Title: http.StatusText(status), Data: msg})
}

func (s *Server) routesWeb(mux *http.ServeMux) {
	css, _ := webFS.ReadFile("web/style.css")
	mux.HandleFunc("GET /static/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(css)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.currentSession(r.Context(), r); err == nil {
			http.Redirect(w, r, "/configs", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("GET /auth/{provider}/login", s.oidcLogin)
	mux.HandleFunc("GET /auth/{provider}/callback", s.oidcCallback)

	mux.Handle("POST /logout", s.withSession(s.logout))
	mux.Handle("GET /configs", s.withSession(s.configsPage))
	mux.Handle("GET /configs/{id}", s.withSession(s.configPage))
	mux.Handle("GET /configs/{id}/revisions/{rev}", s.withSession(s.revisionPage))
	mux.Handle("POST /configs/{id}/revisions/{rev}/restore", s.withSession(s.restoreRevision))
	mux.Handle("GET /devices", s.withSession(s.devicesPage))
	mux.Handle("POST /devices", s.withSession(s.createDevice))
	mux.Handle("POST /devices/revoke-all", s.withSession(s.revokeAllDevices))
	mux.Handle("POST /devices/{id}/revoke", s.withSession(s.revokeDevice))
	mux.Handle("POST /sessions/revoke-others", s.withSession(s.revokeOtherSessions))
	mux.Handle("POST /sessions/{id}/revoke", s.withSession(s.revokeSession))
}

type providerLink struct{ ID, Name string }

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	var links []providerLink
	for _, p := range s.cfg.OIDC {
		links = append(links, providerLink{p.ID, p.Name})
	}
	s.render(w, r, http.StatusOK, "login", page{Title: "Вход", Data: struct {
		Providers []providerLink
		ReturnTo  string
	}{links, safeReturnTo(r.URL.Query().Get("return_to"))}})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess webSession) {
	if err := s.db.DeleteSession(r.Context(), sess.UserID, sess.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(r.Context(), "logout", "err", err)
	}
	clearCookie(w, sessionCookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) configsPage(w http.ResponseWriter, r *http.Request, sess webSession) {
	list, err := s.configs.List(r.Context(), sess.actor())
	if err != nil {
		s.webError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "configs", page{Title: "Конфиги", Session: &sess, Data: struct {
		Configs []configs.Config
		Active  *int64
	}{list, sess.User.ActiveConfigID}})
}

func (s *Server) configPage(w http.ResponseWriter, r *http.Request, sess webSession) {
	id, ok := pathID(r)
	if !ok {
		s.webError(w, r, configs.ErrNotFound)
		return
	}
	c, err := s.configs.Get(r.Context(), sess.actor(), id)
	if err != nil {
		s.webError(w, r, err)
		return
	}
	revs, err := s.configs.Revisions(r.Context(), sess.actor(), id)
	if err != nil {
		s.webError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "config", page{Title: c.Name, Session: &sess, Flash: flash(r), Data: struct {
		Config    configs.Config
		Revisions []store.RevisionInfo
	}{c, revs}})
}

func (s *Server) revisionPage(w http.ResponseWriter, r *http.Request, sess webSession) {
	id, ok1 := pathID(r)
	rev, ok2 := pathRev(r)
	if !ok1 || !ok2 {
		s.webError(w, r, configs.ErrNotFound)
		return
	}
	c, err := s.configs.Get(r.Context(), sess.actor(), id)
	if err != nil {
		s.webError(w, r, err)
		return
	}
	content, err := s.configs.RevisionContent(r.Context(), sess.actor(), id, rev)
	if err != nil {
		s.webError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "revision", page{Title: fmt.Sprintf("%s — ревизия %d", c.Name, rev), Session: &sess,
		Data: struct {
			Config   configs.Config
			Revision int32
			Content  string
		}{c, rev, content}})
}

func (s *Server) restoreRevision(w http.ResponseWriter, r *http.Request, sess webSession) {
	id, ok1 := pathID(r)
	rev, ok2 := pathRev(r)
	version, err := strconv.ParseInt(r.PostForm.Get("version"), 10, 64)
	if !ok1 || !ok2 || err != nil {
		s.webError(w, r, configs.ErrNotFound)
		return
	}
	_, err = s.configs.Restore(r.Context(), sess.actor(), id, rev, version)
	var perr *configs.PreconditionError
	if errors.As(err, &perr) {
		http.Redirect(w, r, fmt.Sprintf("/configs/%d?flash=changed", id), http.StatusSeeOther) //nolint:gosec // local path built from a parsed integer
		return
	}
	if err != nil {
		s.webError(w, r, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/configs/%d?flash=restored", id), http.StatusSeeOther) //nolint:gosec // local path built from a parsed integer
}

// flash maps a fixed set of codes to messages, so the query string cannot
// inject arbitrary text into the page.
func flash(r *http.Request) string {
	switch r.URL.Query().Get("flash") {
	case "restored":
		return "Ревизия восстановлена как новая текущая."
	case "changed":
		return "Конфиг изменился, пока страница была открыта. Проверьте историю и повторите."
	case "revoked":
		return "Отозвано."
	}
	return ""
}

type scopeOption struct {
	Name    string
	Default bool
}

func (s *Server) devicesPage(w http.ResponseWriter, r *http.Request, sess webSession) {
	devs, err := s.db.ListDevices(r.Context(), sess.UserID)
	if err != nil {
		s.webError(w, r, err)
		return
	}
	sessions, err := s.db.ListSessions(r.Context(), sess.UserID)
	if err != nil {
		s.webError(w, r, err)
		return
	}
	var scopes []scopeOption
	for _, sc := range auth.AllScopes {
		scopes = append(scopes, scopeOption{sc, slices.Contains(auth.DefaultScopes, sc)})
	}
	slices.Reverse(devs) // newest first
	s.render(w, r, http.StatusOK, "devices", page{Title: "Устройства", Session: &sess, Flash: flash(r), Data: struct {
		Devices  []store.Device
		Sessions []store.Session
		Scopes   []scopeOption
		Current  uuid.UUID
	}{devs, sessions, scopes, sess.ID}})
}

var allowedTTLs = map[string]time.Duration{"720h": 720 * time.Hour, "2160h": 2160 * time.Hour, "8760h": 8760 * time.Hour, "0": 0}

// createDevice issues a token. It requires a recent login: a stolen or
// left-open session alone must not be enough to mint long-lived credentials.
func (s *Server) createDevice(w http.ResponseWriter, r *http.Request, sess webSession) {
	if time.Since(sess.AuthenticatedAt) > s.cfg.Session.ReauthMaxAge {
		s.render(w, r, http.StatusForbidden, "reauth", page{Title: "Подтвердите вход", Session: &sess,
			Data: struct{ Provider, ReturnTo string }{sess.Provider, "/devices"}})
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" || utf8.RuneCountInString(name) > 100 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		s.renderError(w, r, http.StatusBadRequest, "Название устройства: от 1 до 100 символов.")
		return
	}
	scopes, err := auth.ParseScopes(strings.Join(r.PostForm["scope"], ","))
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Выберите хотя бы одно право.")
		return
	}
	ttl, ok := allowedTTLs[r.PostForm.Get("ttl")]
	if !ok {
		s.renderError(w, r, http.StatusBadRequest, "Некорректный срок действия.")
		return
	}
	token, hash, hint, err := auth.NewToken()
	if err != nil {
		s.webError(w, r, err)
		return
	}
	d := store.Device{ID: uuid.New(), UserID: sess.UserID, Name: name, TokenHint: hint, Scopes: scopes}
	if ttl > 0 {
		exp := time.Now().Add(ttl)
		d.ExpiresAt = &exp
	}
	d, err = s.db.CreateDevice(r.Context(), d, hash)
	if err != nil {
		s.webError(w, r, err)
		return
	}
	s.log.InfoContext(r.Context(), "device token issued", "user_id", sess.UserID, "device_id", d.ID, "via", "web")
	s.render(w, r, http.StatusOK, "token", page{Title: "Новый токен", Session: &sess, Data: struct {
		Name, Token, ServerURL string
		Scopes                 []string
		ExpiresAt              *time.Time
	}{d.Name, token, s.publicURL(r), d.Scopes, d.ExpiresAt}})
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request, sess webSession) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err == nil {
		err = s.db.RevokeDevice(r.Context(), sess.UserID, id)
	}
	if err != nil {
		s.webError(w, r, configs.ErrNotFound)
		return
	}
	s.log.InfoContext(r.Context(), "device token revoked", "user_id", sess.UserID, "device_id", id)
	http.Redirect(w, r, "/devices?flash=revoked", http.StatusSeeOther)
}

func (s *Server) revokeAllDevices(w http.ResponseWriter, r *http.Request, sess webSession) {
	n, err := s.db.RevokeAllDevices(r.Context(), sess.UserID)
	if err != nil {
		s.webError(w, r, err)
		return
	}
	s.log.InfoContext(r.Context(), "all device tokens revoked", "user_id", sess.UserID, "count", n)
	http.Redirect(w, r, "/devices?flash=revoked", http.StatusSeeOther)
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request, sess webSession) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err == nil {
		err = s.db.DeleteSession(r.Context(), sess.UserID, id)
	}
	if err != nil {
		s.webError(w, r, configs.ErrNotFound)
		return
	}
	if id == sess.ID {
		clearCookie(w, sessionCookie)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/devices?flash=revoked", http.StatusSeeOther)
}

func (s *Server) revokeOtherSessions(w http.ResponseWriter, r *http.Request, sess webSession) {
	if _, err := s.db.DeleteOtherSessions(r.Context(), sess.UserID, sess.ID); err != nil {
		s.webError(w, r, err)
		return
	}
	http.Redirect(w, r, "/devices?flash=revoked", http.StatusSeeOther)
}

func (s *Server) webError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, configs.ErrNotFound) || errors.Is(err, store.ErrNotFound) {
		s.renderError(w, r, http.StatusNotFound, "Не найдено.")
		return
	}
	s.log.ErrorContext(r.Context(), "web request failed", "err", err)
	s.renderError(w, r, http.StatusInternalServerError, "")
}

func (s *Server) publicURL(r *http.Request) string {
	if s.cfg.PublicURL != "" {
		return s.cfg.PublicURL
	}
	return "https://" + r.Host
}

func pathRev(r *http.Request) (int32, bool) {
	n, err := strconv.ParseInt(r.PathValue("rev"), 10, 32)
	return int32(n), err == nil && n > 0
}
