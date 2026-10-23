package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"tabbysync/internal/auth"
)

// reqInfo is filled in as the request passes through the stack and logged
// once at the end.
type reqInfo struct {
	id       string
	ip       string
	limitKey string // client network for rate limiting, see clientKey
	deviceID string
}

type reqInfoKey struct{}

func requestIDFrom(ctx context.Context) string {
	if ri, ok := ctx.Value(reqInfoKey{}).(*reqInfo); ok {
		return ri.id
	}
	return ""
}

func infoFrom(ctx context.Context) *reqInfo {
	ri, _ := ctx.Value(reqInfoKey{}).(*reqInfo)
	return ri
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// observe assigns a request ID, recovers panics and writes one access log
// line. The query string and headers are never logged: they may carry
// credentials.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		var idb [12]byte
		_, _ = rand.Read(idb[:])
		addr := clientIP(r, s.cfg.TrustedProxies)
		ri := &reqInfo{id: hex.EncodeToString(idb[:]), ip: addr.String(), limitKey: clientKey(addr)}
		r = r.WithContext(context.WithValue(r.Context(), reqInfoKey{}, ri))
		w.Header().Set("X-Request-ID", ri.id)
		sw := &statusWriter{ResponseWriter: w}

		defer func() {
			if rec := recover(); rec != nil {
				if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(rec)
				}
				s.log.ErrorContext(r.Context(), "panic", "request_id", ri.id, "panic", rec)
				if sw.status == 0 {
					writeProblem(sw, r, http.StatusInternalServerError, "")
				}
			}
			s.log.Log(r.Context(), logLevelFor(sw.status), "http",
				"request_id", ri.id,
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"bytes", sw.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
				"ip", ri.ip,
				"device_id", ri.deviceID,
			)
		}()
		next.ServeHTTP(sw, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	// HSTS covers the whole host and its subdomains; under a base path the
	// origin belongs to someone else's nginx, which sets its own policy.
	hsts := s.cfg.BasePath == ""
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// cors allows browser-based clients (the Electron app loads from file://).
// The API authenticates only with an explicit bearer token, never cookies,
// and credentials are not allowed, so a foreign page can do nothing a script
// without the token could not do anyway.
func (s *Server) cors(next http.Handler) http.Handler {
	wildcard := slices.Contains(s.cfg.CORSOrigins, "*")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Add("Vary", "Origin")
		if !wildcard && !slices.Contains(s.cfg.CORSOrigins, origin) {
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if wildcard {
			h.Set("Access-Control-Allow-Origin", "*")
		} else {
			h.Set("Access-Control-Allow-Origin", origin)
		}
		h.Set("Access-Control-Expose-Headers", "ETag, Location, Repr-Digest, Idempotent-Replayed, Retry-After, X-Request-ID")
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-Match, If-None-Match, Idempotency-Key, Content-Digest, Repr-Digest")
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) limitIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.ipLimit.Allow(infoFrom(r.Context()).limitKey) {
			tooMany(w, r, 1)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func tooMany(w http.ResponseWriter, r *http.Request, retryAfter int) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeProblem(w, r, http.StatusTooManyRequests, "Too many requests.")
}

// authed wraps a handler with bearer authentication and a scope check.
// Tokens are accepted only in the Authorization header: the auth_token query
// parameter Tabby Web supports ends up in proxy logs and browser history.
func (s *Server) authed(scope string, h func(http.ResponseWriter, *http.Request, auth.Actor)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ri := infoFrom(r.Context())
		if s.failLimit.Exhausted(ri.limitKey) {
			tooMany(w, r, 60)
			return
		}
		token, ok := bearer(r)
		if !ok {
			unauthorized(w, r, "")
			return
		}
		actor, err := s.authn.Authenticate(r.Context(), token)
		if errors.Is(err, auth.ErrInvalidToken) {
			s.failLimit.Allow(ri.limitKey)
			unauthorized(w, r, "invalid_token")
			return
		}
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		ri.deviceID = actor.DeviceID.String()
		if !actor.Has(scope) {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+scope+`"`)
			writeProblem(w, r, http.StatusForbidden, "Token lacks scope "+scope+".")
			return
		}
		if !s.deviceLimit.Allow(ri.deviceID) {
			tooMany(w, r, 1)
			return
		}
		if err := s.db.TouchDevice(r.Context(), actor.DeviceID, ri.ip); err != nil {
			s.log.WarnContext(r.Context(), "touch device", "err", err)
		}
		h(w, r, actor)
	})
}

func bearer(r *http.Request) (string, bool) {
	v := r.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(v, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

func unauthorized(w http.ResponseWriter, r *http.Request, code string) {
	v := `Bearer realm="tabby-sync"`
	if code != "" {
		v += `, error="` + code + `"`
	}
	w.Header().Set("WWW-Authenticate", v)
	writeProblem(w, r, http.StatusUnauthorized, "Authentication credentials were not provided or are invalid.")
}
