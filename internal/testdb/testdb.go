// Package testdb gives tests a fresh, migrated Postgres database.
//
// It uses TABBYSYNC_TEST_DATABASE_URL if set (a role allowed to CREATE
// DATABASE); otherwise it starts one Postgres container per test binary via
// testcontainers. Without either, tests are skipped, unless
// TABBYSYNC_REQUIRE_DB=1 (set in CI) turns that into a failure.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"tabbysync/internal/store"
)

var (
	once    sync.Once
	baseURL string
	initErr error
)

func admin(t *testing.T) string {
	t.Helper()
	once.Do(func() {
		if u := os.Getenv("TABBYSYNC_TEST_DATABASE_URL"); u != "" {
			baseURL = u
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		// The container lives until the test binary exits; Ryuk removes it.
		c, err := postgres.Run(ctx, "postgres:17-alpine",
			postgres.WithDatabase("postgres"),
			postgres.WithUsername("postgres"),
			postgres.WithPassword("postgres"),
			postgres.BasicWaitStrategies())
		if err != nil {
			initErr = err
			return
		}
		baseURL, initErr = c.ConnectionString(ctx, "sslmode=disable")
	})
	if initErr != nil || baseURL == "" {
		if os.Getenv("TABBYSYNC_REQUIRE_DB") == "1" {
			t.Fatalf("test database unavailable: %v", initErr)
		}
		t.Skipf("test database unavailable (start Docker or set TABBYSYNC_TEST_DATABASE_URL): %v", initErr)
	}
	return baseURL
}

// URL creates an empty database for this test and returns its URL.
func URL(t *testing.T) string {
	t.Helper()
	if os.Getenv("TABBYSYNC_TEST_DATABASE_URL") == "" && os.Getenv("TABBYSYNC_REQUIRE_DB") != "1" {
		testcontainers.SkipIfProviderIsNotHealthy(t)
	}
	base := admin(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	var b [6]byte
	_, _ = rand.Read(b[:])
	name := "t_" + hex.EncodeToString(b[:])
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err == nil {
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			c.Close(context.Background())
		}
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

// Open returns a store on a fresh migrated database.
func Open(t *testing.T) (*store.Store, string) {
	t.Helper()
	u := URL(t)
	if err := store.Migrate(context.Background(), u, "up"); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db, u
}
