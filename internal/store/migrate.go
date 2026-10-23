package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Migrate runs "up", "down", "status" or "version". It is a separate command
// rather than part of server startup, so the server can run under a database
// role without DDL rights. goose takes a Postgres advisory lock, so two
// concurrent runs cannot interleave.
func Migrate(ctx context.Context, databaseURL, command string) error {
	cfg, err := parseConfig(databaseURL)
	if err != nil {
		return err
	}
	db := stdlib.OpenDB(*cfg.ConnConfig)
	defer db.Close() //nolint:errcheck // nothing to do on failure

	provider, err := newProvider(db)
	if err != nil {
		return err
	}
	switch command {
	case "up":
		res, err := provider.Up(ctx)
		for _, r := range res {
			fmt.Println(r)
		}
		return err
	case "down":
		r, err := provider.Down(ctx)
		if r != nil {
			fmt.Println(r)
		}
		return err
	case "status":
		st, err := provider.Status(ctx)
		for _, s := range st {
			fmt.Printf("%-8s %s\n", s.State, s.Source.Path)
		}
		return err
	case "version":
		v, err := provider.GetDBVersion(ctx)
		fmt.Println(v)
		return err
	}
	return fmt.Errorf("unknown migrate command %q (up, down, status, version)", command)
}

func newProvider(db *sql.DB) (*goose.Provider, error) {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return nil, err
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, err
	}
	return goose.NewProvider(goose.DialectPostgres, db, sub, goose.WithSessionLocker(locker))
}
