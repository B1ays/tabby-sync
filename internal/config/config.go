// Package config loads server settings from the environment.
//
// Every variable is prefixed with TABBYSYNC_. Secrets can be supplied through
// a file instead of the environment by appending _FILE to the name
// (TABBYSYNC_DATABASE_URL_FILE), which works with Docker and Kubernetes secrets.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const prefix = "TABBYSYNC_"

type Config struct {
	Listen      string
	TLSCertFile string
	TLSKeyFile  string

	DatabaseURL string

	KeyringFile string
	KEKPrimary  string

	TrustedProxies []netip.Prefix
	CORSOrigins    []string

	LogLevel slog.Level

	// PublicURL is the externally visible origin (https://sync.example.com),
	// used for OIDC redirect URIs. Required when OIDC is configured.
	PublicURL string
	OIDC      []OIDCProvider
	// Who may sign up on first login (verified email). Users pre-registered
	// by an admin with "syncd user add -email" may always sign in.
	AllowedEmails       []string
	AllowedEmailDomains []string
	Session             Session

	Limits    Limits
	Retention Retention
	RateLimit RateLimit
}

type OIDCProvider struct {
	ID           string // URL path segment, e.g. "google"
	Name         string // shown on the login page
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
}

type Session struct {
	Idle   time.Duration
	MaxAge time.Duration
	// Sensitive actions (issuing a token) need a login at most this old.
	ReauthMaxAge time.Duration
}

type Limits struct {
	MaxConfigBytes    int
	MaxConfigsPerUser int
}

type Retention struct {
	// A revision is pruned only if it is older than the newest KeepMin
	// revisions and either older than MaxAge or beyond HardCap.
	KeepMin    int
	MaxAge     time.Duration
	HardCap    int
	SoftDelete time.Duration
}

type RateLimit struct {
	// Per client IP, applied before authentication.
	IPRate  float64
	IPBurst int
	// Failed authentication attempts per client IP.
	AuthFailPerMinute float64
	AuthFailBurst     int
	// Per authenticated device.
	DeviceRate  float64
	DeviceBurst int
}

func Load() (*Config, error) {
	var errs []error
	l := loader{errs: &errs}

	c := &Config{
		Listen:              l.str("LISTEN", "127.0.0.1:8080"),
		TLSCertFile:         l.str("TLS_CERT_FILE", ""),
		TLSKeyFile:          l.str("TLS_KEY_FILE", ""),
		DatabaseURL:         l.secret("DATABASE_URL"),
		KeyringFile:         l.str("KEYRING_FILE", ""),
		KEKPrimary:          l.str("KEK_PRIMARY", ""),
		CORSOrigins:         l.list("CORS_ALLOWED_ORIGINS", "*"),
		LogLevel:            l.level("LOG_LEVEL", slog.LevelInfo),
		PublicURL:           strings.TrimSuffix(l.str("PUBLIC_URL", ""), "/"),
		AllowedEmails:       lower(l.list("ALLOWED_EMAILS", "")),
		AllowedEmailDomains: lower(l.list("ALLOWED_EMAIL_DOMAINS", "")),
		Session: Session{
			Idle:         l.dur("SESSION_IDLE", 30*time.Minute),
			MaxAge:       l.dur("SESSION_MAX_AGE", 12*time.Hour),
			ReauthMaxAge: l.dur("REAUTH_MAX_AGE", 15*time.Minute),
		},
		Limits: Limits{
			MaxConfigBytes:    l.int("MAX_CONFIG_BYTES", 2<<20),
			MaxConfigsPerUser: l.int("MAX_CONFIGS_PER_USER", 100),
		},
		Retention: Retention{
			KeepMin:    l.int("REVISIONS_KEEP_MIN", 20),
			MaxAge:     l.dur("REVISIONS_MAX_AGE", 30*24*time.Hour),
			HardCap:    l.int("REVISIONS_HARD_CAP", 500),
			SoftDelete: l.dur("SOFT_DELETE_RETENTION", 30*24*time.Hour),
		},
		RateLimit: RateLimit{
			IPRate:            l.float("RATE_IP_RPS", 20),
			IPBurst:           l.int("RATE_IP_BURST", 60),
			AuthFailPerMinute: l.float("RATE_AUTH_FAIL_PER_MIN", 10),
			AuthFailBurst:     l.int("RATE_AUTH_FAIL_BURST", 10),
			DeviceRate:        l.float("RATE_DEVICE_RPS", 5),
			DeviceBurst:       l.int("RATE_DEVICE_BURST", 30),
		},
	}
	for _, s := range l.list("TRUSTED_PROXIES", "") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			if a, aerr := netip.ParseAddr(s); aerr == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				errs = append(errs, fmt.Errorf("%sTRUSTED_PROXIES: %q is not an IP or CIDR", prefix, s))
				continue
			}
		}
		c.TrustedProxies = append(c.TrustedProxies, p.Masked())
	}

	for _, id := range l.list("OIDC_PROVIDERS", "") {
		if !providerIDRe.MatchString(id) {
			errs = append(errs, fmt.Errorf("%sOIDC_PROVIDERS: %q must match %s", prefix, id, providerIDRe))
			continue
		}
		p := "OIDC_" + strings.ToUpper(id) + "_"
		op := OIDCProvider{
			ID:           id,
			Name:         l.str(p+"NAME", id),
			Issuer:       l.str(p+"ISSUER", ""),
			ClientID:     l.str(p+"CLIENT_ID", ""),
			ClientSecret: l.secret(p + "CLIENT_SECRET"),
			Scopes:       l.list(p+"SCOPES", "openid,email,profile"),
		}
		if op.Issuer == "" || op.ClientID == "" || op.ClientSecret == "" {
			errs = append(errs, fmt.Errorf("%s%sISSUER, CLIENT_ID and CLIENT_SECRET are required", prefix, p))
		} else if !strings.HasPrefix(op.Issuer, "https://") {
			errs = append(errs, fmt.Errorf("%s%sISSUER must be https", prefix, p))
		}
		c.OIDC = append(c.OIDC, op)
	}
	if len(c.OIDC) > 0 && !strings.HasPrefix(c.PublicURL, "https://") {
		errs = append(errs, errors.New(prefix+"PUBLIC_URL (https://...) is required with OIDC"))
	}
	if c.Session.Idle <= 0 || c.Session.MaxAge < c.Session.Idle || c.Session.ReauthMaxAge <= 0 {
		errs = append(errs, errors.New("SESSION_IDLE must be positive and <= SESSION_MAX_AGE; REAUTH_MAX_AGE positive"))
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		errs = append(errs, errors.New("TLS_CERT_FILE and TLS_KEY_FILE must be set together"))
	}
	if c.Limits.MaxConfigBytes < 1024 || c.Limits.MaxConfigsPerUser < 1 {
		errs = append(errs, errors.New("MAX_CONFIG_BYTES must be >= 1024 and MAX_CONFIGS_PER_USER >= 1"))
	}
	if c.Retention.KeepMin < 1 || c.Retention.HardCap < c.Retention.KeepMin {
		errs = append(errs, errors.New("REVISIONS_KEEP_MIN must be >= 1 and <= REVISIONS_HARD_CAP"))
	}
	return c, errors.Join(errs...)
}

// RequireDB and RequireKeys are checked by the commands that need them, so
// that e.g. "keys generate" works without a database.
func (c *Config) RequireDB() error {
	if c.DatabaseURL == "" {
		return errors.New(prefix + "DATABASE_URL (or _FILE) is required")
	}
	return nil
}

func (c *Config) RequireKeys() error {
	if c.KeyringFile == "" || c.KEKPrimary == "" {
		return errors.New(prefix + "KEYRING_FILE and " + prefix + "KEK_PRIMARY are required")
	}
	return nil
}

var providerIDRe = regexp.MustCompile(`^[a-z0-9]{1,32}$`)

func lower(s []string) []string {
	for i := range s {
		s[i] = strings.ToLower(s[i])
	}
	return s
}

type loader struct{ errs *[]error }

func (l loader) str(name, def string) string {
	if v, ok := os.LookupEnv(prefix + name); ok {
		return strings.TrimSpace(v)
	}
	return def
}

func (l loader) secret(name string) string {
	if v := l.str(name, ""); v != "" {
		return v
	}
	path := l.str(name+"_FILE", "")
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path) //nolint:gosec // the path is operator configuration

	if err != nil {
		*l.errs = append(*l.errs, fmt.Errorf("%s%s_FILE: %w", prefix, name, err))
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (l loader) list(name, def string) []string {
	var out []string
	for _, s := range strings.Split(l.str(name, def), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (l loader) int(name string, def int) int {
	s := l.str(name, "")
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		*l.errs = append(*l.errs, fmt.Errorf("%s%s: %w", prefix, name, err))
	}
	return v
}

func (l loader) float(name string, def float64) float64 {
	s := l.str(name, "")
	if s == "" {
		return def
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v <= 0 {
		*l.errs = append(*l.errs, fmt.Errorf("%s%s: must be a positive number", prefix, name))
	}
	return v
}

func (l loader) dur(name string, def time.Duration) time.Duration {
	s := l.str(name, "")
	if s == "" {
		return def
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		*l.errs = append(*l.errs, fmt.Errorf("%s%s: %w", prefix, name, err))
	}
	return v
}

func (l loader) level(name string, def slog.Level) slog.Level {
	s := l.str(name, "")
	if s == "" {
		return def
	}
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(s)); err != nil {
		*l.errs = append(*l.errs, fmt.Errorf("%s%s: %w", prefix, name, err))
	}
	return lv
}
