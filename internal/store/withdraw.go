// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
	"zoli.dev/intel-feed/internal/model"
)

// Retractions expose the previously approved record, never private replacement evidence.
func retractPublic(ctx context.Context, tx *sql.Tx, id string, revision int, at time.Time, reviewer, rationale string) (bool, error) {
	var b []byte
	err := tx.QueryRowContext(ctx, "SELECT record FROM public_records WHERE id=$1", id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var p model.Record
	if err = json.Unmarshal(b, &p); err != nil {
		return false, err
	}
	p.Status = "withdrawn"
	p.WithdrawnAt = &at
	p.ModifiedAt = at
	p.Revision = revision
	p.Reviews = append(p.Reviews, model.Review{Action: "withdraw", Reviewer: reviewer, Rationale: rationale, At: at, Revision: revision})
	return true, savePublic(ctx, tx, p)
}
