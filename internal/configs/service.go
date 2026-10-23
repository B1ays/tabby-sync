// Package configs holds the rules for reading and writing synced configs:
// every content change becomes a new encrypted revision, writes to one config
// are serialised by a row lock, and an optional expected version turns a
// would-be lost update into a precondition failure.
package configs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"tabbysync/internal/auth"
	"tabbysync/internal/crypto"
	"tabbysync/internal/store"
)

var (
	ErrNotFound      = errors.New("config not found")
	ErrTooManyConfig = errors.New("config limit reached")
)

// PreconditionError means the client's expected version is stale.
type PreconditionError struct{ Current int64 }

func (e *PreconditionError) Error() string {
	return fmt.Sprintf("config was modified (current version %d)", e.Current)
}

type Limits struct {
	MaxConfigBytes    int
	MaxConfigsPerUser int
}

type Service struct {
	DB        *store.Store
	Keys      *crypto.Keyring
	Limits    Limits
	Retention store.Retention
	Log       *slog.Logger
}

// Config is the decrypted view of a config.
type Config struct {
	ID                  int64
	UserID              int64
	Name                string
	Content             string
	Version             int64
	Revision            int32
	LastUsedWithVersion *string
	CreatedAt           time.Time
	ModifiedAt          time.Time
}

// Optional distinguishes "absent" from "set" (and, for nullable fields, null).
type Optional[T any] struct {
	Set   bool
	Value T
}

func Some[T any](v T) Optional[T] { return Optional[T]{Set: true, Value: v} }

type Patch struct {
	Name                Optional[string]
	Content             Optional[string]
	LastUsedWithVersion Optional[*string]
	// IfVersion, when set, must equal the config's current version.
	IfVersion Optional[int64]
}

const emptyContent = "{}"

func (s *Service) List(ctx context.Context, a auth.Actor) ([]Config, error) {
	rows, err := s.DB.ListConfigs(ctx, a.UserID)
	if err != nil {
		return nil, err
	}
	out := make([]Config, 0, len(rows))
	for _, r := range rows {
		c, err := s.decrypt(r)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, a auth.Actor, id int64) (Config, error) {
	r, err := s.DB.GetConfig(ctx, a.UserID, id)
	if errors.Is(err, store.ErrNotFound) {
		return Config{}, ErrNotFound
	}
	if err != nil {
		return Config{}, err
	}
	return s.decrypt(r)
}

func (s *Service) Create(ctx context.Context, a auth.Actor, p Patch) (Config, error) {
	var out Config
	err := s.DB.InTx(ctx, func(q *store.Queries) (err error) {
		out, err = s.CreateTx(ctx, q, a, p)
		return err
	})
	return out, err
}

// CreateTx is Create inside the caller's transaction.
func (s *Service) CreateTx(ctx context.Context, q *store.Queries, a auth.Actor, p Patch) (Config, error) {
	name := fmt.Sprintf("Unnamed config (%s)", time.Now().UTC().Format(time.DateOnly))
	if p.Name.Set {
		name = p.Name.Value // "" is rejected below, as Tabby Web does
	}
	content := emptyContent
	if p.Content.Set {
		content = p.Content.Value
	}
	var lastUsed *string
	if p.LastUsedWithVersion.Set {
		lastUsed = p.LastUsedWithVersion.Value
	}
	if err := s.validate(name, content, lastUsed); err != nil {
		return Config{}, err
	}
	if _, err := q.LockUser(ctx, a.UserID); err != nil {
		return Config{}, err
	}
	n, err := q.CountLiveConfigs(ctx, a.UserID)
	if err != nil {
		return Config{}, err
	}
	if n >= s.Limits.MaxConfigsPerUser {
		return Config{}, ErrTooManyConfig
	}
	c, err := q.InsertConfig(ctx, a.UserID, name, lastUsed)
	if err != nil {
		return Config{}, err
	}
	if _, err := s.insertRevision(ctx, q, a, c.ID, 1, content); err != nil {
		return Config{}, err
	}
	s.Log.InfoContext(ctx, "config created", "config_id", c.ID, "user_id", a.UserID, "device_id", a.DeviceID)
	return fromRow(c, content), nil
}

func (s *Service) Update(ctx context.Context, a auth.Actor, id int64, p Patch) (Config, error) {
	var out Config
	err := s.DB.InTx(ctx, func(q *store.Queries) (err error) {
		out, err = s.UpdateTx(ctx, q, a, id, p)
		return err
	})
	return out, err
}

// UpdateTx is Update inside the caller's transaction.
func (s *Service) UpdateTx(ctx context.Context, q *store.Queries, a auth.Actor, id int64, p Patch) (Config, error) {
	// Only fields being changed are validated, so lowering a limit does not
	// make existing configs impossible to rename.
	if err := s.validatePatch(p); err != nil {
		return Config{}, err
	}
	cur, err := s.lock(ctx, q, a, id, p.IfVersion)
	if err != nil {
		return Config{}, err
	}
	curContent, err := s.open(cur.Current)
	if err != nil {
		return Config{}, err
	}

	name, content, lastUsed := cur.Name, curContent, cur.LastUsedWithVersion
	if p.Name.Set {
		name = p.Name.Value
	}
	if p.Content.Set {
		content = p.Content.Value
	}
	if p.LastUsedWithVersion.Set {
		lastUsed = p.LastUsedWithVersion.Value
	}

	contentChanged := content != curContent
	if !contentChanged && name == cur.Name && equalPtr(lastUsed, cur.LastUsedWithVersion) {
		return fromRow(cur.Config, curContent), nil
	}
	rev := cur.CurrentRevision
	if contentChanged {
		rev++
		if _, err := s.insertRevision(ctx, q, a, id, rev, content); err != nil {
			return Config{}, err
		}
	}
	c, err := q.UpdateConfig(ctx, a.UserID, id, store.ConfigUpdate{
		Name:                name,
		LastUsedWithVersion: lastUsed,
		CurrentRevision:     rev,
		Touch:               contentChanged || name != cur.Name,
	})
	if err != nil {
		return Config{}, err
	}
	if contentChanged {
		if _, err := q.PruneRevisions(ctx, id, rev, s.Retention); err != nil {
			return Config{}, err
		}
		// Without If-Match the client may be overwriting a change it
		// never saw. The previous revision stays in history either way.
		s.Log.InfoContext(ctx, "config content updated",
			"config_id", id, "user_id", a.UserID, "device_id", a.DeviceID,
			"revision", rev, "conditional", p.IfVersion.Set)
	}
	return fromRow(c, content), nil
}

// lock takes the config's row lock and checks the expected version.
func (s *Service) lock(ctx context.Context, q *store.Queries, a auth.Actor, id int64, ifVersion Optional[int64]) (store.ConfigWithContent, error) {
	cur, err := q.LockConfig(ctx, a.UserID, id)
	if errors.Is(err, store.ErrNotFound) {
		return cur, ErrNotFound
	}
	if err != nil {
		return cur, err
	}
	if ifVersion.Set && ifVersion.Value != cur.Version {
		return cur, &PreconditionError{Current: cur.Version}
	}
	return cur, nil
}

func (s *Service) Delete(ctx context.Context, a auth.Actor, id int64) error {
	return s.DB.InTx(ctx, func(q *store.Queries) error {
		return s.DeleteTx(ctx, q, a, id, Optional[int64]{})
	})
}

// DeleteTx soft-deletes a config inside the caller's transaction, if its
// version matches ifVersion when that is set.
func (s *Service) DeleteTx(ctx context.Context, q *store.Queries, a auth.Actor, id int64, ifVersion Optional[int64]) error {
	if _, err := s.lock(ctx, q, a, id, ifVersion); err != nil {
		return err
	}
	if err := q.SoftDeleteConfig(ctx, a.UserID, id); err != nil {
		return err
	}
	if err := q.ClearActiveConfig(ctx, a.UserID, id); err != nil {
		return err
	}
	s.Log.InfoContext(ctx, "config deleted", "config_id", id, "user_id", a.UserID, "device_id", a.DeviceID)
	return nil
}

func (s *Service) validate(name, content string, lastUsed *string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if lastUsed != nil {
		if err := validateAppVersion(*lastUsed); err != nil {
			return err
		}
	}
	return validateContent(content, s.Limits.MaxConfigBytes)
}

func (s *Service) validatePatch(p Patch) error {
	if p.Name.Set {
		if err := validateName(p.Name.Value); err != nil {
			return err
		}
	}
	if p.LastUsedWithVersion.Set && p.LastUsedWithVersion.Value != nil {
		if err := validateAppVersion(*p.LastUsedWithVersion.Value); err != nil {
			return err
		}
	}
	if p.Content.Set {
		return validateContent(p.Content.Value, s.Limits.MaxConfigBytes)
	}
	return nil
}

func (s *Service) insertRevision(ctx context.Context, q *store.Queries, a auth.Actor, configID int64, rev int32, content string) (store.Revision, error) {
	sealed, err := s.Keys.Seal([]byte(content), crypto.Binding{UserID: a.UserID, ConfigID: configID, Revision: rev})
	if err != nil {
		return store.Revision{}, err
	}
	var dev *uuid.UUID
	if a.DeviceID != uuid.Nil { // nil for changes made in the web UI
		dev = &a.DeviceID
	}
	return q.InsertRevision(ctx, store.Revision{
		ConfigID:   configID,
		UserID:     a.UserID,
		Revision:   rev,
		Ciphertext: sealed.Ciphertext,
		DEKWrapped: sealed.WrappedDEK,
		KEKID:      sealed.KEKID,
		Size:       int32(len(content)),
		DeviceID:   dev,
	})
}

func (s *Service) open(r store.Revision) (string, error) {
	pt, err := s.Keys.Open(
		crypto.Sealed{Ciphertext: r.Ciphertext, WrappedDEK: r.DEKWrapped, KEKID: r.KEKID},
		crypto.Binding{UserID: r.UserID, ConfigID: r.ConfigID, Revision: r.Revision})
	if err != nil {
		// Tampered row, wrong keyring or a bug: never return partial data.
		return "", fmt.Errorf("config %d revision %d: %w", r.ConfigID, r.Revision, err)
	}
	return string(pt), nil
}

func (s *Service) decrypt(r store.ConfigWithContent) (Config, error) {
	content, err := s.open(r.Current)
	if err != nil {
		return Config{}, err
	}
	return fromRow(r.Config, content), nil
}

func fromRow(c store.Config, content string) Config {
	return Config{
		ID:                  c.ID,
		UserID:              c.UserID,
		Name:                c.Name,
		Content:             content,
		Version:             c.Version,
		Revision:            c.CurrentRevision,
		LastUsedWithVersion: c.LastUsedWithVersion,
		CreatedAt:           c.CreatedAt,
		ModifiedAt:          c.ModifiedAt,
	}
}

func equalPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
