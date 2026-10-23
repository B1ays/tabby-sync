package httpapi_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"tabbysync/internal/auth"
	"tabbysync/internal/config"
	"tabbysync/internal/configs"
	"tabbysync/internal/crypto"
	"tabbysync/internal/httpapi"
	"tabbysync/internal/store"
	"tabbysync/internal/testdb"
)

// TestPreview serves the web UI with a fake identity provider and sample
// data at http://localhost:18080 for ten minutes, for manual inspection:
//
//	TABBYSYNC_PREVIEW=1 go test -run TestPreview -timeout 15m ./internal/httpapi
func TestPreview(t *testing.T) {
	if os.Getenv("TABBYSYNC_PREVIEW") != "1" {
		t.Skip("set TABBYSYNC_PREVIEW=1")
	}
	db, _ := testdb.Open(t)
	line, _ := crypto.GenerateKeyLine("k1")
	keys, _ := crypto.ParseKeyring(strings.NewReader(line), "k1")
	idp := newFakeIdP(t)
	idp.AuthTime = time.Now().Add(time.Hour) // every login counts as fresh

	cfg := &config.Config{
		CORSOrigins: []string{"*"},
		PublicURL:   "http://localhost:18080",
		OIDC: []config.OIDCProvider{{ID: "test", Name: "Test IdP", Issuer: idp.srv.URL,
			ClientID: idpClientID, ClientSecret: idpClientSecret, Scopes: []string{"openid", "email"}}},
		AllowedEmailDomains: []string{"example.com"},
		Session:             config.Session{Idle: 30 * time.Minute, MaxAge: 12 * time.Hour, ReauthMaxAge: 15 * time.Minute},
		Limits:              config.Limits{MaxConfigBytes: 64 << 10, MaxConfigsPerUser: 5},
		RateLimit: config.RateLimit{IPRate: 1e4, IPBurst: 1e4, AuthFailPerMinute: 1e4, AuthFailBurst: 1e4,
			DeviceRate: 1e4, DeviceBurst: 1e4},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &configs.Service{DB: db, Keys: keys, Log: log,
		Limits:    configs.Limits{MaxConfigBytes: 64 << 10, MaxConfigsPerUser: 5},
		Retention: store.Retention{KeepMin: 1000, MaxAge: time.Hour, HardCap: 10000}}

	ctx := context.Background()
	u, _ := db.CreateUserWithEmail(ctx, "alice@example.com", ptr("alice@example.com"))
	_, hash, hint, _ := auth.NewToken()
	dev, _ := db.CreateDevice(ctx, store.Device{ID: uuid.New(), UserID: u.ID, Name: "Рабочий ноутбук",
		TokenHint: hint, Scopes: auth.DefaultScopes}, hash)
	a := auth.Actor{UserID: u.ID, DeviceID: dev.ID}
	c, _ := svc.Create(ctx, a, configs.Patch{Name: configs.Some("Основной"), Content: configs.Some("version: 3\nprofiles: []\n")})
	for _, s := range []string{"version: 3\nprofiles:\n  - name: prod\n    type: ssh\n", "version: 3\nappearance:\n  font: Fira Code\nprofiles:\n  - name: prod\n    type: ssh\n"} {
		_, _ = svc.Update(ctx, a, c.ID, configs.Patch{Content: configs.Some(s), LastUsedWithVersion: configs.Some(ptr("1.0.230"))})
	}

	ln, err := net.Listen("tcp", "127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: httpapi.New(cfg, log, db, svc, httpapi.WithOIDCClient(idp.srv.Client())).Handler(),
		ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Log("preview at http://localhost:18080")
	time.Sleep(10 * time.Minute)
	_ = srv.Close()
}
