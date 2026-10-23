package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"tabbysync/internal/auth"
	"tabbysync/internal/config"
	"tabbysync/internal/store"
)

const flowTTL = 10 * time.Minute

// oidcProvider performs discovery lazily and retries on failure, so the
// server starts even while an identity provider is unreachable.
type oidcProvider struct {
	cfg      config.OIDCProvider
	redirect string
	client   *http.Client

	mu       sync.Mutex
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func newOIDCProviders(cfg *config.Config, client *http.Client) map[string]*oidcProvider {
	out := map[string]*oidcProvider{}
	for _, p := range cfg.OIDC {
		out[p.ID] = &oidcProvider{
			cfg:      p,
			redirect: cfg.PublicURL + "/auth/" + p.ID + "/callback",
			client:   client,
		}
	}
	return out
}

func (p *oidcProvider) ctx(ctx context.Context) context.Context {
	ctx = oidc.ClientContext(ctx, p.client)
	return context.WithValue(ctx, oauth2.HTTPClient, p.client)
}

func (p *oidcProvider) init(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.oauth != nil {
		return p.oauth, p.verifier, nil
	}
	// The provider keeps the client from this context for fetching keys
	// later, so it must not be tied to the request's lifetime.
	dctx, cancel := context.WithTimeout(p.ctx(context.WithoutCancel(ctx)), 10*time.Second)
	defer cancel()
	prov, err := oidc.NewProvider(dctx, p.cfg.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discovery for %s: %w", p.cfg.ID, err)
	}
	p.oauth = &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		Endpoint:     prov.Endpoint(),
		RedirectURL:  p.redirect,
		Scopes:       p.cfg.Scopes,
	}
	p.verifier = prov.Verifier(&oidc.Config{ClientID: p.cfg.ClientID})
	return p.oauth, p.verifier, nil
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// safeReturnTo accepts only local absolute paths, so the login flow cannot
// be used as an open redirect.
func safeReturnTo(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") ||
		strings.ContainsAny(s, "\\\r\n\t") || strings.HasPrefix(s, "/auth/") {
		return "/configs"
	}
	return s
}

// GET /auth/{provider}/login
func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	p, ok := s.providers[r.PathValue("provider")]
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Неизвестный провайдер входа.")
		return
	}
	oauthCfg, _, err := p.init(r.Context())
	if err != nil {
		s.log.ErrorContext(r.Context(), "oidc init", "err", err)
		s.renderError(w, r, http.StatusBadGateway, "Провайдер входа недоступен, попробуйте позже.")
		return
	}

	flowID := randomString(32)
	flow := store.OIDCFlow{
		Provider:     p.cfg.ID,
		State:        randomString(32),
		Nonce:        randomString(32),
		PKCEVerifier: oauth2.GenerateVerifier(),
		ReturnTo:     safeReturnTo(r.URL.Query().Get("return_to")),
		Reauth:       r.URL.Query().Get("reauth") == "1",
		ExpiresAt:    time.Now().Add(flowTTL),
	}
	if err := s.db.CreateOIDCFlow(r.Context(), auth.HashToken(flowID), flow); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "")
		s.log.ErrorContext(r.Context(), "create oidc flow", "err", err)
		return
	}
	s.setCookie(w, s.flowCookie, flowID, flowTTL)

	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(flow.PKCEVerifier), oidc.Nonce(flow.Nonce)}
	if flow.Reauth {
		opts = append(opts, oauth2.SetAuthURLParam("max_age", "0"), oauth2.SetAuthURLParam("prompt", "login"))
	}
	http.Redirect(w, r, oauthCfg.AuthCodeURL(flow.State, opts...), http.StatusFound)
}

type idClaims struct {
	Email         string          `json:"email"`
	EmailVerified json.RawMessage `json:"email_verified"`
	AuthTime      int64           `json:"auth_time"`
}

// verified handles providers that send email_verified as a string.
func (c idClaims) verified() bool {
	v := strings.Trim(string(c.EmailVerified), `"`)
	return v == "true"
}

var errLoginRejected = errors.New("login rejected")

// GET /auth/{provider}/callback
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fail := func(status int, msg string, logMsg string, args ...any) {
		s.log.WarnContext(ctx, "oidc login failed: "+logMsg, args...)
		s.renderError(w, r, status, msg)
	}

	c, err := r.Cookie(s.flowCookie)
	s.clearCookie(w, s.flowCookie)
	if err != nil {
		fail(http.StatusBadRequest, "Сеанс входа не найден или истёк. Начните вход заново.", "no flow cookie")
		return
	}
	flow, err := s.db.TakeOIDCFlow(ctx, auth.HashToken(c.Value))
	if err != nil {
		fail(http.StatusBadRequest, "Сеанс входа не найден или истёк. Начните вход заново.", "flow not found", "err", err)
		return
	}
	q := r.URL.Query()
	if flow.Provider != r.PathValue("provider") ||
		subtle.ConstantTimeCompare([]byte(flow.State), []byte(q.Get("state"))) != 1 {
		fail(http.StatusBadRequest, "Неверный параметр state. Начните вход заново.", "state mismatch")
		return
	}
	if e := q.Get("error"); e != "" {
		fail(http.StatusForbidden, "Провайдер отклонил вход.", "provider error", "error", e)
		return
	}
	p := s.providers[flow.Provider]
	oauthCfg, verifier, err := p.init(ctx)
	if err != nil {
		fail(http.StatusBadGateway, "Провайдер входа недоступен.", "init", "err", err)
		return
	}
	tok, err := oauthCfg.Exchange(p.ctx(ctx), q.Get("code"), oauth2.VerifierOption(flow.PKCEVerifier))
	if err != nil {
		fail(http.StatusBadRequest, "Не удалось завершить вход.", "code exchange", "err", err)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		fail(http.StatusBadRequest, "Провайдер не вернул ID token.", "no id_token")
		return
	}
	// Checks signature, issuer, audience and expiry.
	idt, err := verifier.Verify(p.ctx(ctx), raw)
	if err != nil {
		fail(http.StatusBadRequest, "Не удалось проверить ответ провайдера.", "verify id_token", "err", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(flow.Nonce)) != 1 {
		fail(http.StatusBadRequest, "Неверный nonce. Начните вход заново.", "nonce mismatch")
		return
	}
	var claims idClaims
	if err := idt.Claims(&claims); err != nil {
		fail(http.StatusBadRequest, "Не удалось прочитать ответ провайдера.", "claims", "err", err)
		return
	}
	if flow.Reauth {
		// The provider must attest that the user authenticated during this
		// flow, not just reuse an old single sign-on session.
		at := time.Unix(claims.AuthTime, 0)
		if claims.AuthTime == 0 || at.Before(flow.CreatedAt.Add(-time.Minute)) {
			fail(http.StatusForbidden, "Провайдер не подтвердил повторный вход.", "reauth without fresh auth_time")
			return
		}
	}

	user, err := s.resolveUser(ctx, idt.Issuer, idt.Subject, claims)
	if errors.Is(err, errLoginRejected) {
		fail(http.StatusForbidden, "Для этой учётной записи доступ не разрешён. Обратитесь к администратору.",
			"user not allowed", "issuer", idt.Issuer, "subject", idt.Subject)
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "resolve user", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "")
		return
	}
	if user.DisabledAt != nil {
		fail(http.StatusForbidden, "Учётная запись отключена.", "user disabled", "user_id", user.ID)
		return
	}

	if err := s.startSession(w, r, user, flow.Provider); err != nil {
		s.log.ErrorContext(ctx, "start session", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "")
		return
	}
	s.log.InfoContext(ctx, "web login", "user_id", user.ID, "provider", flow.Provider, "reauth", flow.Reauth)
	s.redirect(w, r, flow.ReturnTo, http.StatusSeeOther)
}

// resolveUser maps an OIDC identity to a user. Identity is (issuer,
// subject); email is used only once, to link a first login to an account
// an admin registered, or to allow sign-up from the allow-list. It must be
// verified by the provider.
func (s *Server) resolveUser(ctx context.Context, issuer, subject string, c idClaims) (store.User, error) {
	u, err := s.db.UserByIdentity(ctx, issuer, subject)
	if !errors.Is(err, store.ErrNotFound) {
		return u, err
	}
	email := strings.ToLower(strings.TrimSpace(c.Email))
	if a, perr := mail.ParseAddress(email); perr != nil || a.Address != email || !c.verified() {
		return store.User{}, errLoginRejected
	}
	u, err = s.db.LinkIdentityByEmail(ctx, email, issuer, subject)
	if !errors.Is(err, store.ErrNotFound) {
		return u, err
	}
	if !s.signupAllowed(email) {
		return store.User{}, errLoginRejected
	}
	u, err = s.db.CreateUserWithIdentity(ctx, email, email, issuer, subject)
	if store.IsUniqueViolation(err) {
		// The email belongs to an account already linked to another identity.
		return store.User{}, errLoginRejected
	}
	return u, err
}

func (s *Server) signupAllowed(email string) bool {
	if slices.Contains(s.cfg.AllowedEmails, email) {
		return true
	}
	_, domain, _ := strings.Cut(email, "@")
	return slices.Contains(s.cfg.AllowedEmailDomains, domain)
}
