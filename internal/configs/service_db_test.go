package configs_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"tabbysync/internal/auth"
	"tabbysync/internal/configs"
	"tabbysync/internal/crypto"
	"tabbysync/internal/store"
	"tabbysync/internal/testdb"
)

type fixture struct {
	db    *store.Store
	raw   *pgxpool.Pool
	svc   *configs.Service
	actor auth.Actor
	lines []string
}

func setup(t *testing.T, retention store.Retention) *fixture {
	t.Helper()
	db, url := testdb.Open(t)
	raw, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(raw.Close)

	l1, _ := crypto.GenerateKeyLine("k1")
	l2, _ := crypto.GenerateKeyLine("k2")
	keys, _ := crypto.ParseKeyring(strings.NewReader(l1), "k1")

	ctx := context.Background()
	u, err := db.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	_, hash, hint, _ := auth.NewToken()
	d, err := db.CreateDevice(ctx, store.Device{ID: uuid.New(), UserID: u.ID, Name: "d", TokenHint: hint, Scopes: auth.AllScopes}, hash)
	if err != nil {
		t.Fatal(err)
	}
	svc := &configs.Service{
		DB: db, Keys: keys, Retention: retention,
		Limits: configs.Limits{MaxConfigBytes: 1 << 20, MaxConfigsPerUser: 10},
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return &fixture{db: db, raw: raw, svc: svc, actor: auth.Actor{UserID: u.ID, DeviceID: d.ID}, lines: []string{l1, l2}}
}

var keepAll = store.Retention{KeepMin: 1000, MaxAge: time.Hour, HardCap: 10000}

func TestContentIsEncryptedAtRest(t *testing.T) {
	f := setup(t, keepAll)
	ctx := context.Background()
	secret := "password: hunter2-very-secret"
	c, err := f.svc.Create(ctx, f.actor, configs.Patch{Content: configs.Some(secret)})
	if err != nil {
		t.Fatal(err)
	}
	var ct []byte
	if err := f.raw.QueryRow(ctx, `SELECT ciphertext FROM config_revisions WHERE config_id = $1`, c.ID).Scan(&ct); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("hunter2")) {
		t.Fatal("plaintext stored")
	}
	// Nothing in the database dump should contain it either.
	var hits int
	if err := f.raw.QueryRow(ctx,
		`SELECT count(*) FROM config_revisions WHERE position('hunter2'::bytea in ciphertext) > 0`).Scan(&hits); err != nil || hits != 0 {
		t.Fatalf("hits %d err %v", hits, err)
	}
}

func TestSwappedCiphertextIsRejected(t *testing.T) {
	f := setup(t, keepAll)
	ctx := context.Background()
	a, _ := f.svc.Create(ctx, f.actor, configs.Patch{Content: configs.Some("which: a")})
	b, _ := f.svc.Create(ctx, f.actor, configs.Patch{Content: configs.Some("which: b")})

	// A database-level attacker copies config a's encrypted row into b.
	// The trigger forbids UPDATE, so delete and re-insert.
	var ct, dek []byte
	var kek string
	if err := f.raw.QueryRow(ctx, `SELECT ciphertext, dek_wrapped, kek_id FROM config_revisions WHERE config_id = $1`, a.ID).
		Scan(&ct, &dek, &kek); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(ctx, `DELETE FROM config_revisions WHERE config_id = $1`, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(ctx, `
		INSERT INTO config_revisions (config_id, user_id, revision, ciphertext, dek_wrapped, kek_id, size)
		VALUES ($1, $2, 1, $3, $4, $5, 8)`, b.ID, f.actor.UserID, ct, dek, kek); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Get(ctx, f.actor, b.ID); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("Get after swap: %v, want ErrDecrypt", err)
	}
}

func TestVerify(t *testing.T) {
	f := setup(t, keepAll)
	ctx := context.Background()
	var ids []int64
	for i := range 3 {
		c, _ := f.svc.Create(ctx, f.actor, configs.Patch{Content: configs.Some(fmt.Sprintf("n: %d", i))})
		_, _ = f.svc.Update(ctx, f.actor, c.ID, configs.Patch{Content: configs.Some(fmt.Sprintf("n: %d0", i))})
		ids = append(ids, c.ID)
	}
	rep, err := f.svc.Verify(ctx)
	if err != nil || rep.Revisions != 6 || len(rep.Problems) != 0 {
		t.Fatalf("clean: %+v %v", rep, err)
	}

	// Move a ciphertext to another config and drop a current revision.
	if _, err := f.raw.Exec(ctx, `ALTER TABLE config_revisions DISABLE TRIGGER config_revisions_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(ctx, `UPDATE config_revisions SET ciphertext = (SELECT ciphertext FROM config_revisions WHERE config_id = $1 AND revision = 1)
		WHERE config_id = $2 AND revision = 1`, ids[0], ids[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(ctx, `DELETE FROM config_revisions WHERE config_id = $1 AND revision = 2`, ids[2]); err != nil {
		t.Fatal(err)
	}
	rep, err = f.svc.Verify(ctx)
	if err != nil || len(rep.Problems) != 2 {
		t.Fatalf("tampered: %+v %v", rep, err)
	}
}

func TestRevisionsAreImmutable(t *testing.T) {
	f := setup(t, keepAll)
	ctx := context.Background()
	c, _ := f.svc.Create(ctx, f.actor, configs.Patch{})
	for _, q := range []string{
		`UPDATE config_revisions SET ciphertext = '\x00' WHERE config_id = $1`,
		`UPDATE config_revisions SET revision = 7 WHERE config_id = $1`,
		`UPDATE config_revisions SET created_at = now() - interval '1 year' WHERE config_id = $1`,
	} {
		if _, err := f.raw.Exec(ctx, q, c.ID); err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Errorf("%s: err = %v", q, err)
		}
	}
	// Rewrapping the data key is allowed.
	if _, err := f.raw.Exec(ctx, `UPDATE config_revisions SET kek_id = kek_id WHERE config_id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRetention(t *testing.T) {
	f := setup(t, store.Retention{KeepMin: 3, MaxAge: time.Hour, HardCap: 5})
	ctx := context.Background()
	c, _ := f.svc.Create(ctx, f.actor, configs.Patch{})
	for i := range 9 {
		if _, err := f.svc.Update(ctx, f.actor, c.ID, configs.Patch{Content: configs.Some(fmt.Sprintf("n: %d", i))}); err != nil {
			t.Fatal(err)
		}
	}
	// 10 revisions, all younger than MaxAge: only HardCap applies.
	if got := revisions(t, f, c.ID); got != "6,7,8,9,10" {
		t.Fatalf("after hard cap: %s", got)
	}
	// Age the history; now everything beyond KeepMin goes.
	if _, err := f.raw.Exec(ctx, `ALTER TABLE config_revisions DISABLE TRIGGER config_revisions_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(ctx, `UPDATE config_revisions SET created_at = now() - interval '2 hours'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Update(ctx, f.actor, c.ID, configs.Patch{Content: configs.Some("n: last")}); err != nil {
		t.Fatal(err)
	}
	if got := revisions(t, f, c.ID); got != "9,10,11" {
		t.Fatalf("after age: %s", got)
	}
}

func revisions(t *testing.T, f *fixture, configID int64) string {
	t.Helper()
	var s string
	if err := f.raw.QueryRow(context.Background(),
		`SELECT string_agg(revision::text, ',' ORDER BY revision) FROM config_revisions WHERE config_id = $1`, configID).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKeyRotation(t *testing.T) {
	f := setup(t, keepAll)
	ctx := context.Background()
	var ids []int64
	for i := range 3 {
		c, err := f.svc.Create(ctx, f.actor, configs.Patch{Content: configs.Some(fmt.Sprintf("i: %d", i))})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, c.ID)
	}

	// Add k2 as primary, keep k1 for reading, rewrap.
	both, _ := crypto.ParseKeyring(strings.NewReader(f.lines[0]+"\n"+f.lines[1]), "k2")
	f.svc.Keys = both
	n, err := f.svc.RewrapAll(ctx)
	if err != nil || n != 3 {
		t.Fatalf("RewrapAll = %d, %v", n, err)
	}
	if n, _ := f.svc.RewrapAll(ctx); n != 0 {
		t.Fatalf("second RewrapAll = %d", n)
	}

	// k1 can now be dropped.
	f.svc.Keys, _ = crypto.ParseKeyring(strings.NewReader(f.lines[1]), "k2")
	for i, id := range ids {
		c, err := f.svc.Get(ctx, f.actor, id)
		if err != nil || c.Content != fmt.Sprintf("i: %d", i) {
			t.Fatalf("config %d after rotation: %+v %v", id, c, err)
		}
	}
}

func TestPurgeDeleted(t *testing.T) {
	f := setup(t, keepAll)
	ctx := context.Background()
	c, _ := f.svc.Create(ctx, f.actor, configs.Patch{})
	if err := f.svc.Delete(ctx, f.actor, c.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.db.PurgeDeletedConfigs(ctx, time.Now().Add(-time.Hour)); n != 0 {
		t.Fatalf("purged %d before retention", n)
	}
	if n, _ := f.db.PurgeDeletedConfigs(ctx, time.Now().Add(time.Second)); n != 1 {
		t.Fatalf("purged %d after retention", n)
	}
	var left int
	_ = f.raw.QueryRow(ctx, `SELECT count(*) FROM config_revisions WHERE config_id = $1`, c.ID).Scan(&left)
	if left != 0 {
		t.Fatalf("%d revisions left", left)
	}
}

func TestMigrationsRoundTrip(t *testing.T) {
	_, url := testdb.Open(t)
	ctx := context.Background()
	if err := store.Migrate(ctx, url, "down"); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, url, "up"); err != nil {
		t.Fatal(err)
	}
}
