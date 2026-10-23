package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Config struct {
	ID                  int64
	UserID              int64
	Name                string
	Version             int64
	CurrentRevision     int32
	LastUsedWithVersion *string
	CreatedAt           time.Time
	ModifiedAt          time.Time
}

type Revision struct {
	ConfigID   int64
	UserID     int64
	Revision   int32
	Ciphertext []byte
	DEKWrapped []byte
	KEKID      string
	Size       int32
	DeviceID   *uuid.UUID
	CreatedAt  time.Time
}

// ConfigWithContent is a config joined with its current revision.
type ConfigWithContent struct {
	Config
	Current Revision
}

const configWithContentSelect = `
	SELECT c.id, c.user_id, c.name, c.version, c.current_revision, c.last_used_with_version,
	       c.created_at, c.modified_at,
	       r.config_id, r.user_id, r.revision, r.ciphertext, r.dek_wrapped, r.kek_id, r.size,
	       r.device_id, r.created_at
	FROM configs c
	JOIN config_revisions r ON r.config_id = c.id AND r.revision = c.current_revision
	WHERE c.user_id = $1 AND c.deleted_at IS NULL`

func scanConfigWithContent(row interface{ Scan(...any) error }) (ConfigWithContent, error) {
	var c ConfigWithContent
	r := &c.Current
	err := row.Scan(&c.ID, &c.UserID, &c.Name, &c.Version, &c.CurrentRevision, &c.LastUsedWithVersion,
		&c.CreatedAt, &c.ModifiedAt,
		&r.ConfigID, &r.UserID, &r.Revision, &r.Ciphertext, &r.DEKWrapped, &r.KEKID, &r.Size,
		&r.DeviceID, &r.CreatedAt)
	return c, notFound(err)
}

func (q *Queries) ListConfigs(ctx context.Context, userID int64) ([]ConfigWithContent, error) {
	rows, err := q.db.Query(ctx, configWithContentSelect+` ORDER BY c.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConfigWithContent
	for rows.Next() {
		c, err := scanConfigWithContent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (q *Queries) GetConfig(ctx context.Context, userID, id int64) (ConfigWithContent, error) {
	return scanConfigWithContent(q.db.QueryRow(ctx, configWithContentSelect+` AND c.id = $2`, userID, id))
}

// LockConfig locks a live config row until the end of the transaction and
// reads it with its current revision.
//
// The lock is taken by a query on configs alone. A single locking query
// joined to config_revisions would lose the row under concurrency: after
// waiting for another writer, READ COMMITTED re-checks the join against the
// old snapshot, which cannot see the revision that writer just inserted.
// The second statement gets a fresh snapshot that does.
func (q *Queries) LockConfig(ctx context.Context, userID, id int64) (ConfigWithContent, error) {
	var lockedID int64
	err := q.db.QueryRow(ctx,
		`SELECT id FROM configs WHERE id = $2 AND user_id = $1 AND deleted_at IS NULL FOR UPDATE`,
		userID, id).Scan(&lockedID)
	if err != nil {
		return ConfigWithContent{}, notFound(err)
	}
	return q.GetConfig(ctx, userID, id)
}

func (q *Queries) CountLiveConfigs(ctx context.Context, userID int64) (int, error) {
	var n int
	err := q.db.QueryRow(ctx,
		`SELECT count(*) FROM configs WHERE user_id = $1 AND deleted_at IS NULL`, userID).Scan(&n)
	return n, err
}

// InsertConfig creates the config row pointing at revision 1. The caller must
// insert that revision in the same transaction.
func (q *Queries) InsertConfig(ctx context.Context, userID int64, name string, lastUsed *string) (Config, error) {
	var c Config
	err := q.db.QueryRow(ctx, `
		INSERT INTO configs (user_id, name, current_revision, last_used_with_version)
		VALUES ($1, $2, 1, $3)
		RETURNING id, user_id, name, version, current_revision, last_used_with_version, created_at, modified_at`,
		userID, name, lastUsed).
		Scan(&c.ID, &c.UserID, &c.Name, &c.Version, &c.CurrentRevision, &c.LastUsedWithVersion,
			&c.CreatedAt, &c.ModifiedAt)
	return c, err
}

func (q *Queries) InsertRevision(ctx context.Context, r Revision) (Revision, error) {
	err := q.db.QueryRow(ctx, `
		INSERT INTO config_revisions (config_id, user_id, revision, ciphertext, dek_wrapped, kek_id, size, device_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at`,
		r.ConfigID, r.UserID, r.Revision, r.Ciphertext, r.DEKWrapped, r.KEKID, r.Size, r.DeviceID).
		Scan(&r.CreatedAt)
	return r, err
}

type ConfigUpdate struct {
	Name                string
	LastUsedWithVersion *string
	CurrentRevision     int32
	// Touch bumps modified_at. Clients poll modified_at to decide whether to
	// download, so it only moves when name or content actually change.
	Touch bool
}

func (q *Queries) UpdateConfig(ctx context.Context, userID, id int64, u ConfigUpdate) (Config, error) {
	var c Config
	err := q.db.QueryRow(ctx, `
		UPDATE configs SET
		    name = $3,
		    last_used_with_version = $4,
		    current_revision = $5,
		    version = version + 1,
		    modified_at = CASE WHEN $6 THEN clock_timestamp() ELSE modified_at END
		WHERE id = $2 AND user_id = $1 AND deleted_at IS NULL
		RETURNING id, user_id, name, version, current_revision, last_used_with_version, created_at, modified_at`,
		userID, id, u.Name, u.LastUsedWithVersion, u.CurrentRevision, u.Touch).
		Scan(&c.ID, &c.UserID, &c.Name, &c.Version, &c.CurrentRevision, &c.LastUsedWithVersion,
			&c.CreatedAt, &c.ModifiedAt)
	return c, notFound(err)
}

func (q *Queries) SoftDeleteConfig(ctx context.Context, userID, id int64) error {
	tag, err := q.db.Exec(ctx, `
		UPDATE configs SET deleted_at = now(), version = version + 1
		WHERE id = $2 AND user_id = $1 AND deleted_at IS NULL`, userID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

type Retention struct {
	KeepMin int
	MaxAge  time.Duration
	HardCap int
}

// PruneRevisions drops old history of one config. The newest KeepMin
// revisions (which include the current one) are always kept.
func (q *Queries) PruneRevisions(ctx context.Context, configID int64, current int32, r Retention) (int64, error) {
	tag, err := q.db.Exec(ctx, `
		DELETE FROM config_revisions
		WHERE config_id = $1
		  AND revision <= $2::integer - $3::integer
		  AND (created_at < now() - make_interval(secs => $4::double precision)
		       OR revision <= $2::integer - $5::integer)`,
		configID, current, r.KeepMin, r.MaxAge.Seconds(), r.HardCap)
	return tag.RowsAffected(), err
}

// PurgeDeletedConfigs permanently removes configs soft-deleted before the
// cutoff, together with their revisions.
func (q *Queries) PurgeDeletedConfigs(ctx context.Context, before time.Time) (int64, error) {
	tag, err := q.db.Exec(ctx, `DELETE FROM configs WHERE deleted_at < $1`, before)
	return tag.RowsAffected(), err
}

// RevisionInfo is a history entry without its content.
type RevisionInfo struct {
	Revision   int32
	Size       int32
	CreatedAt  time.Time
	DeviceName *string
}

// ListRevisions returns the history of a live config, newest first.
func (q *Queries) ListRevisions(ctx context.Context, userID, configID int64) ([]RevisionInfo, error) {
	rows, err := q.db.Query(ctx, `
		SELECT r.revision, r.size, r.created_at, d.name
		FROM config_revisions r
		JOIN configs c ON c.id = r.config_id AND c.user_id = r.user_id
		LEFT JOIN devices d ON d.id = r.device_id
		WHERE r.user_id = $1 AND r.config_id = $2 AND c.deleted_at IS NULL
		ORDER BY r.revision DESC`, userID, configID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevisionInfo
	for rows.Next() {
		var r RevisionInfo
		if err := rows.Scan(&r.Revision, &r.Size, &r.CreatedAt, &r.DeviceName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRevision returns one revision of a live config owned by userID.
func (q *Queries) GetRevision(ctx context.Context, userID, configID int64, revision int32) (Revision, error) {
	var r Revision
	err := q.db.QueryRow(ctx, `
		SELECT r.config_id, r.user_id, r.revision, r.ciphertext, r.dek_wrapped, r.kek_id, r.size, r.device_id, r.created_at
		FROM config_revisions r
		JOIN configs c ON c.id = r.config_id AND c.user_id = r.user_id
		WHERE r.user_id = $1 AND r.config_id = $2 AND r.revision = $3 AND c.deleted_at IS NULL`,
		userID, configID, revision).
		Scan(&r.ConfigID, &r.UserID, &r.Revision, &r.Ciphertext, &r.DEKWrapped, &r.KEKID, &r.Size, &r.DeviceID, &r.CreatedAt)
	return r, notFound(err)
}

// ScanRevisions pages through all revisions in key order, starting after
// (afterConfig, afterRev). Used for integrity checks.
func (q *Queries) ScanRevisions(ctx context.Context, afterConfig int64, afterRev int32, limit int) ([]Revision, error) {
	rows, err := q.db.Query(ctx, `
		SELECT config_id, user_id, revision, ciphertext, dek_wrapped, kek_id, size, device_id, created_at
		FROM config_revisions
		WHERE (config_id, revision) > ($1, $2)
		ORDER BY config_id, revision LIMIT $3`, afterConfig, afterRev, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Revision
	for rows.Next() {
		var r Revision
		if err := rows.Scan(&r.ConfigID, &r.UserID, &r.Revision, &r.Ciphertext, &r.DEKWrapped,
			&r.KEKID, &r.Size, &r.DeviceID, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ConfigsWithoutCurrentRevision returns live configs whose current
// revision row is missing, which should never happen.
func (q *Queries) ConfigsWithoutCurrentRevision(ctx context.Context) ([]int64, error) {
	rows, err := q.db.Query(ctx, `
		SELECT c.id FROM configs c
		LEFT JOIN config_revisions r ON r.config_id = c.id AND r.revision = c.current_revision
		WHERE c.deleted_at IS NULL AND r.config_id IS NULL
		ORDER BY c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RevisionsNotUnderKEK returns revisions whose data key is wrapped by a key
// other than kekID, locking them for rewrapping.
func (q *Queries) RevisionsNotUnderKEK(ctx context.Context, kekID string, limit int) ([]Revision, error) {
	rows, err := q.db.Query(ctx, `
		SELECT config_id, user_id, revision, ciphertext, dek_wrapped, kek_id, size, device_id, created_at
		FROM config_revisions WHERE kek_id <> $1
		ORDER BY config_id, revision LIMIT $2
		FOR UPDATE SKIP LOCKED`, kekID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Revision
	for rows.Next() {
		var r Revision
		if err := rows.Scan(&r.ConfigID, &r.UserID, &r.Revision, &r.Ciphertext, &r.DEKWrapped,
			&r.KEKID, &r.Size, &r.DeviceID, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (q *Queries) UpdateRevisionKey(ctx context.Context, configID int64, revision int32, wrapped []byte, kekID string) error {
	_, err := q.db.Exec(ctx,
		`UPDATE config_revisions SET dek_wrapped = $3, kek_id = $4 WHERE config_id = $1 AND revision = $2`,
		configID, revision, wrapped, kekID)
	return err
}
