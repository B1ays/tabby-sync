// Package httpapi is the HTTP interface of the sync server.
package httpapi

import (
	"context"
	"crypto/tls"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"tabbysync/internal/auth"
	"tabbysync/internal/config"
	"tabbysync/internal/configs"
	"tabbysync/internal/store"
)

type Server struct {
	cfg     *config.Config
	log     *slog.Logger
	db      *store.Store
	configs *configs.Service
	authn   *auth.Authenticator

	ipLimit     *keyedLimiter
	failLimit   *keyedLimiter
	deviceLimit *keyedLimiter

	providers map[string]*oidcProvider
	tmpl      map[string]*template.Template

	sessionCookie, flowCookie, cookiePath string
}

// Option customises a Server; used by tests.
type Option func(*Server)

// WithOIDCClient sets the HTTP client used to talk to identity providers.
func WithOIDCClient(c *http.Client) Option {
	return func(s *Server) { s.providers = newOIDCProviders(s.cfg, c) }
}

func New(cfg *config.Config, log *slog.Logger, db *store.Store, svc *configs.Service, opts ...Option) *Server {
	rl := cfg.RateLimit
	s := &Server{
		cfg:         cfg,
		log:         log,
		db:          db,
		configs:     svc,
		authn:       &auth.Authenticator{DB: db},
		ipLimit:     newKeyedLimiter(rl.IPRate, rl.IPBurst),
		failLimit:   newKeyedLimiter(rl.AuthFailPerMinute/60, rl.AuthFailBurst),
		deviceLimit: newKeyedLimiter(rl.DeviceRate, rl.DeviceBurst),
		providers:   newOIDCProviders(cfg, &http.Client{Timeout: 10 * time.Second}),
		tmpl:        loadTemplates(cfg.BasePath),
	}
	s.setCookieNames()
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", s.ready)
	s.routesV1(mux)
	s.routesV2(mux)

	// The browser UI authenticates with a cookie, so it gets CSRF
	// protection; the bearer-token API must stay reachable from the
	// Electron app's file:// origin and never reads cookies.
	web := http.NewServeMux()
	s.routesWeb(web)
	cop := http.NewCrossOriginProtection()
	if origin := s.cfg.PublicOrigin(); origin != "" {
		_ = cop.AddTrustedOrigin(origin)
	}
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.log.WarnContext(r.Context(), "cross-origin request blocked", "path", r.URL.Path)
		s.renderError(w, r, http.StatusForbidden, "Запрос с другого сайта отклонён.")
	}))
	mux.Handle("/", cop.Handler(web))

	h := s.observe(s.securityHeaders(s.cors(s.limitIP(mux))))
	if base := s.cfg.BasePath; base != "" {
		// Everything lives under base; anything else is not ours (404).
		strip := http.StripPrefix(base, h)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == base {
				target := base + "/"
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
				// The target starts with the validated base path; a query
				// after "?" cannot change the host.
				http.Redirect(w, r, target, http.StatusMovedPermanently) //nolint:gosec // see above
				return
			}
			strip.ServeHTTP(w, r)
		})
	}
	return h
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.db.Ping(ctx); err != nil {
		s.log.WarnContext(r.Context(), "readiness check failed", "err", err)
		writeProblem(w, r, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// bodyLimit leaves room for JSON escaping of the config content.
func (s *Server) bodyLimit() int64 { return int64(s.cfg.Limits.MaxConfigBytes)*2 + 64<<10 }

// Run serves until ctx is cancelled, then drains in-flight requests.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	go s.sweepLimiters(ctx)

	errc := make(chan error, 1)
	go func() {
		s.log.Info("listening", "addr", s.cfg.Listen, "tls", s.cfg.TLSCertFile != "")
		if s.cfg.TLSCertFile != "" {
			errc <- srv.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	s.log.Info("shutting down")
	// ctx is already cancelled; give in-flight requests their own deadline.
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

func (s *Server) sweepLimiters(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.ipLimit.Sweep()
			s.failLimit.Sweep()
			s.deviceLimit.Sweep()
		}
	}
}
