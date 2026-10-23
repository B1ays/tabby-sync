package configs

import (
	"context"
	"fmt"

	"tabbysync/internal/crypto"
	"tabbysync/internal/store"
)

// VerifyReport is the result of Verify.
type VerifyReport struct {
	Revisions int
	Problems  []string
}

// Verify decrypts every stored revision and checks that each live config
// has its current revision. It only reads, so it can run against a live
// database or a restored backup.
func (s *Service) Verify(ctx context.Context) (VerifyReport, error) {
	var rep VerifyReport
	missing, err := s.DB.ConfigsWithoutCurrentRevision(ctx)
	if err != nil {
		return rep, err
	}
	for _, id := range missing {
		rep.Problems = append(rep.Problems, fmt.Sprintf("config %d: current revision missing", id))
	}
	var afterConfig int64
	var afterRev int32
	for {
		revs, err := s.DB.ScanRevisions(ctx, afterConfig, afterRev, 500)
		if err != nil {
			return rep, err
		}
		if len(revs) == 0 {
			return rep, nil
		}
		for _, r := range revs {
			rep.Revisions++
			pt, err := s.open(r)
			switch {
			case err != nil:
				rep.Problems = append(rep.Problems, err.Error())
			case len(pt) != int(r.Size):
				rep.Problems = append(rep.Problems, fmt.Sprintf("config %d revision %d: size %d, recorded %d",
					r.ConfigID, r.Revision, len(pt), r.Size))
			}
		}
		last := revs[len(revs)-1]
		afterConfig, afterRev = last.ConfigID, last.Revision
	}
}

// RewrapAll moves every revision's data key under the primary KEK, in small
// transactions, so an old KEK can be removed from the keyring afterwards.
func (s *Service) RewrapAll(ctx context.Context) (int, error) {
	total := 0
	for {
		n := 0
		err := s.DB.InTx(ctx, func(q *store.Queries) error {
			revs, err := q.RevisionsNotUnderKEK(ctx, s.Keys.PrimaryID(), 100)
			if err != nil {
				return err
			}
			for _, r := range revs {
				sealed, changed, err := s.Keys.Rewrap(
					crypto.Sealed{Ciphertext: r.Ciphertext, WrappedDEK: r.DEKWrapped, KEKID: r.KEKID},
					crypto.Binding{UserID: r.UserID, ConfigID: r.ConfigID, Revision: r.Revision})
				if err != nil {
					return err
				}
				if !changed {
					continue
				}
				if err := q.UpdateRevisionKey(ctx, r.ConfigID, r.Revision, sealed.WrappedDEK, sealed.KEKID); err != nil {
					return err
				}
				n++
			}
			return nil
		})
		total += n
		if err != nil || n == 0 {
			return total, err
		}
	}
}
