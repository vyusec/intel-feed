// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"encoding/json"
	"errors"
	"zoli.dev/intel-feed/internal/model"
)

// Followup is durable work created only if its originating job still owns its lease.
type Followup struct {
	Kind, Key string
	Payload   any
	Priority  int
}

// CompleteStatic commits the result, private candidate and follow-up jobs together.
// A superseded worker must never revise an approved report or enqueue artifacts.
func (s *Store) CompleteStatic(ctx context.Context, j Job, result any, candidate *model.Record, next []Followup) error {
	if j.Kind != "static" && j.Kind != "static-artifact" {
		return errors.New("static completion requires a static job")
	}
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `UPDATE jobs SET status='done',result=$4,finished_at=now(),lease_until=NULL,lease_token=NULL
 WHERE id=$1 AND lease_token=$2 AND kind=$3 AND status='running' AND lease_until>clock_timestamp()`, j.ID, j.LeaseToken, j.Kind, b)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("static lease expired or superseded")
	}
	if candidate != nil {
		if err = ingest(ctx, tx, *candidate, false); err != nil {
			return err
		}
	}
	for _, f := range next {
		payload, err := json.Marshal(f.Payload)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO jobs(kind,dedup_key,payload,priority) VALUES($1,$2,$3,$4) ON CONFLICT(dedup_key) DO NOTHING", f.Kind, f.Key, payload, f.Priority); err != nil {
			return err
		}
	}
	return tx.Commit()
}
