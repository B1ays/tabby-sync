package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	"tabbysync/internal/auth"
	"tabbysync/internal/store"
)

// The __Host- prefix makes the browser insist on Secure, Path=/ and no
// Domain attribute, so a sibling subdomain cannot set or overwrite it.
const sessionCookie = "__Host-tabbysync_session"

func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// webSession is the signed-in browser user of a request.
type webSession struct {
	store.Session
	User  store.User
	token string
}

// csrfToken is derived from the session secret, so it needs no storage and
// cannot be computed without the cookie. It complements the Sec-Fetch-Site /
// Origin check for browsers that send neither header.
func (s webSession) csrfToken() string {
	h := sha256.Sum256([]byte("tabby-sync csrf v1\x00" + s.token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (s webSession) actor() auth.Actor {
	return auth.Actor{UserID: s.UserID, Scopes: auth.AllScopes}
}

// startSession issues a fresh session ID on every login (no fixation) and
// ends the session the browser had before, if any.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u store.User, provider string) error {
	ctx := r.Context()
	if old, err := r.Cookie(sessionCookie); err == nil {
		if prev, err := s.db.ActiveSession(ctx, auth.HashToken(old.Value), s.cfg.Session.Idle); err == nil {
			_ = s.db.DeleteSession(ctx, prev.UserID, prev.ID)
		}
	}
	token := randomString(32)
	ip := infoFrom(ctx).ip
	ua := truncate(r.UserAgent(), 256)
	_, err := s.db.CreateSession(ctx, auth.HashToken(token), store.Session{
		ID:        uuid.New(),
		UserID:    u.ID,
		Provider:  provider,
		ExpiresAt: time.Now().Add(s.cfg.Session.MaxAge),
		IP:        &ip,
		UserAgent: &ua,
	})
	if err != nil {
		return err
	}
	setCookie(w, sessionCookie, token, s.cfg.Session.MaxAge)
	return nil
}

func (s *Server) currentSession(ctx context.Context, r *http.Request) (webSession, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || !auth.ValidTokenSyntax(c.Value) {
		return webSession{}, store.ErrNotFound
	}
	sess, err := s.db.ActiveSession(ctx, auth.HashToken(c.Value), s.cfg.Session.Idle)
	if err != nil {
		return webSession{}, err
	}
	u, err := s.db.GetUser(ctx, sess.UserID)
	if err != nil {
		return webSession{}, err
	}
	if err := s.db.TouchSession(ctx, sess.ID); err != nil {
		s.log.WarnContext(ctx, "touch session", "err", err)
	}
	return webSession{Session: sess, User: u, token: c.Value}, nil
}

// withSession requires a signed-in user. Unsafe methods additionally need
// the CSRF form token; the cross-origin check runs earlier in the chain.
func (s *Server) withSession(h func(http.ResponseWriter, *http.Request, webSession)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.currentSession(r.Context(), r)
		if errors.Is(err, store.ErrNotFound) {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			s.renderError(w, r, http.StatusUnauthorized, "Сессия истекла. Войдите снова.")
			return
		}
		if err != nil {
			s.log.ErrorContext(r.Context(), "load session", "err", err)
			s.renderError(w, r, http.StatusInternalServerError, "")
			return
		}
		infoFrom(r.Context()).deviceID = "web:" + sess.ID.String()
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				s.renderError(w, r, http.StatusBadRequest, "Некорректная форма.")
				return
			}
			got := r.PostForm.Get("csrf")
			if subtle.ConstantTimeCompare([]byte(got), []byte(sess.csrfToken())) != 1 {
				s.log.WarnContext(r.Context(), "csrf token mismatch", "user_id", sess.UserID)
				s.renderError(w, r, http.StatusForbidden, "Форма устарела. Обновите страницу и повторите.")
				return
			}
		}
		h(w, r, sess)
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 { // do not split a UTF-8 sequence
		n--
	}
	return s[:n]
}
