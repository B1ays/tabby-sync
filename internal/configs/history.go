package configs

import (
	"context"
	"errors"

	"tabbysync/internal/auth"
	"tabbysync/internal/store"
)

// Revisions lists a config's history, newest first.
func (s *Service) Revisions(ctx context.Context, a auth.Actor, id int64) ([]store.RevisionInfo, error) {
	revs, err := s.DB.ListRevisions(ctx, a.UserID, id)
	if err != nil {
		return nil, err
	}
	if len(revs) == 0 {
		return nil, ErrNotFound
	}
	return revs, nil
}

// RevisionContent decrypts one revision.
func (s *Service) RevisionContent(ctx context.Context, a auth.Actor, id int64, rev int32) (string, error) {
	return s.revisionContent(ctx, s.DB.Queries, a, id, rev)
}

func (s *Service) revisionContent(ctx context.Context, q *store.Queries, a auth.Actor, id int64, rev int32) (string, error) {
	r, err := q.GetRevision(ctx, a.UserID, id, rev)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return s.open(r)
}

// Restore makes an old revision current again by writing its content as a
// new revision, so the history in between is kept. ifVersion guards against
// restoring over a change the user has not seen.
func (s *Service) Restore(ctx context.Context, a auth.Actor, id int64, rev int32, ifVersion int64) (Config, error) {
	var out Config
	err := s.DB.InTx(ctx, func(q *store.Queries) (err error) {
		out, err = s.RestoreTx(ctx, q, a, id, rev, ifVersion)
		return err
	})
	return out, err
}

// RestoreTx is Restore inside the caller's transaction.
func (s *Service) RestoreTx(ctx context.Context, q *store.Queries, a auth.Actor, id int64, rev int32, ifVersion int64) (Config, error) {
	content, err := s.revisionContent(ctx, q, a, id, rev)
	if err != nil {
		return Config{}, err
	}
	c, err := s.UpdateTx(ctx, q, a, id, Patch{Content: Some(content), IfVersion: Some(ifVersion)})
	if err == nil {
		s.Log.InfoContext(ctx, "config restored", "config_id", id, "user_id", a.UserID, "from_revision", rev)
	}
	return c, err
}
