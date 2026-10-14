// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// CompleteRuntime fences completion and creates its review-evidence outbox atomically.
func (s *Store) CompleteRuntime(ctx context.Context, j Job, result any) error {
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, "UPDATE jobs SET status='done',result=$3,finished_at=now(),lease_until=NULL,lease_token=NULL WHERE id=$1 AND lease_token=$2 AND kind='runtime' AND status='running' AND lease_until>now()", j.ID, j.LeaseToken, b)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("runtime lease expired or superseded")
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO jobs(kind,dedup_key,payload,priority) VALUES('runtime-evidence',$1,$2,100) ON CONFLICT(dedup_key) DO NOTHING", fmt.Sprintf("runtime-evidence:%d:%s", j.ID, j.LeaseToken), b)
	if err != nil {
		return err
	}
	return tx.Commit()
}
