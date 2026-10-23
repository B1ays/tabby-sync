// Package store is the Postgres data access layer. All SQL is static and
// parameterised; every query on user data is scoped by user_id.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("store: not found")

// DBTX is satisfied by both the pool and a transaction.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Queries struct{ db DBTX }

type Store struct {
	*Queries
	pool *pgxpool.Pool
}

func parseConfig(url string) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		// pgx errors can echo the connection string, which contains the password.
		return nil, errors.New("store: invalid database URL")
	}
	rp := cfg.ConnConfig.RuntimeParams
	rp["application_name"] = "tabby-sync"
	if _, ok := rp["statement_timeout"]; !ok {
		rp["statement_timeout"] = "15s"
	}
	if _, ok := rp["idle_in_transaction_session_timeout"]; !ok {
		rp["idle_in_transaction_session_timeout"] = "30s"
	}
	return cfg, nil
}

func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := parseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.MaxConnLifetime = time.Hour
	cfg.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{Queries: &Queries{db: pool}, pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// InTx runs fn in a READ COMMITTED transaction. Callers that read-modify-write
// lock the rows they change with SELECT ... FOR UPDATE.
func (s *Store) InTx(ctx context.Context, fn func(q *Queries) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return fn(&Queries{db: tx})
	})
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// IsUniqueViolation reports whether err is a unique constraint violation.
func IsUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}
