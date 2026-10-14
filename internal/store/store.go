// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"time"
	"zoli.dev/intel-feed/internal/model"
)

//go:embed schema.sql
var schema string

type Store struct{ DB *sql.DB }

func Open(ctx context.Context, dsn string) (*Store, error) {
	if dsn == "" {
		return nil, errors.New("DATABASE_URL is required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(4)
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db}, nil
}
func (s *Store) Migrate(ctx context.Context) error {
	return s.Lock(ctx, "migrate", func() error { _, e := s.DB.ExecContext(ctx, schema); return e })
}

var ErrLocked = errors.New("another operation holds this lock")

func (s *Store) Lock(ctx context.Context, key string, fn func() error) error {
	c, err := s.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	var ok bool
	if err = c.QueryRowContext(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", key).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrLocked
	}
	defer c.ExecContext(context.Background(), "SELECT pg_advisory_unlock(hashtextextended($1,0))", key)
	return fn()
}
func (s *Store) Ingest(ctx context.Context, r model.Record, auto bool) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if len(r.Sources) == 0 {
		return errors.New("source required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "report:"+r.ID); err != nil {
		return err
	}
	var data []byte
	var oldHash string
	err = tx.QueryRowContext(ctx, "SELECT record,content_hash FROM reports WHERE id=$1 FOR UPDATE", r.ID).Scan(&data, &oldHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	hash := r.ContentHash()
	if err == nil && hash == oldHash {
		return tx.Commit()
	}
	// Shared aliases link reports, but conflicting scopes/verdicts need review.
	if auto && len(r.Aliases) > 0 {
		rows, e := tx.QueryContext(ctx, "SELECT record FROM reports WHERE id<>$1 AND source<>$2 AND (record->'aliases') ?| $3", r.ID, r.Sources[0].Source, pq.Array(r.Aliases))
		if e != nil {
			return e
		}
		incoming, _ := json.Marshal(r.Affected)
		for rows.Next() {
			var otherBytes []byte
			var other model.Record
			if e = rows.Scan(&otherBytes); e != nil {
				rows.Close()
				return e
			}
			if e = json.Unmarshal(otherBytes, &other); e != nil {
				rows.Close()
				return e
			}
			affected, _ := json.Marshal(other.Affected)
			if model.Hash(incoming) != model.Hash(affected) || r.Classification != other.Classification {
				auto = false
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	now := time.Now().UTC()
	r.Revision = 1
	r.Status = "pending"
	r.ModifiedAt = now
	if len(data) > 0 {
		var old model.Record
		if err = json.Unmarshal(data, &old); err != nil {
			return err
		}
		r.Revision = old.Revision + 1
		r.Reviews = append([]model.Review{}, old.Reviews...)
	}
	if auto {
		r.Status = "published"
		r.Reviews = append(r.Reviews, model.Review{Action: "import", Reviewer: "source-policy", Rationale: "Attributed malware report from configured trusted source", At: now, Revision: r.Revision})
	}
	if r.WithdrawnAt != nil {
		r.Status = "withdrawn"
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO reports(id,content_hash,record,source,source_id) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(id) DO UPDATE SET content_hash=excluded.content_hash,record=excluded.record,updated_at=now()`, r.ID, hash, b, r.Sources[0].Source, r.Sources[0].ID)
	if err != nil {
		return err
	}
	if err = saveRevision(ctx, tx, r); err != nil {
		return err
	}
	if r.Status == "published" {
		if err = savePublic(ctx, tx, r); err != nil {
			return err
		}
	} else {
		reason := "Changed source report awaits review"
		if r.Status == "withdrawn" {
			reason = "Upstream report withdrawn or absent from completed reconciliation"
		}
		existed, err := retractPublic(ctx, tx, r.ID, r.Revision, now, "source-policy", reason)
		if err != nil {
			return err
		}
		if !existed && r.Status == "withdrawn" && auto {
			if err = savePublic(ctx, tx, r); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
func saveRevision(ctx context.Context, tx *sql.Tx, r model.Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO report_revisions(id,revision,record) VALUES($1,$2,$3)", r.ID, r.Revision, b)
	return err
}
func savePublic(ctx context.Context, tx *sql.Tx, r model.Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO public_records(id,record) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET record=excluded.record", r.ID, b)
	return err
}
func (s *Store) Review(ctx context.Context, id, action, reviewer, rationale, classification string, expected int) (model.Record, error) {
	var r model.Record
	if reviewer == "" || rationale == "" || expected < 1 {
		return r, errors.New("reviewer, rationale and expected revision are required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	var b []byte
	if err = tx.QueryRowContext(ctx, "SELECT record FROM reports WHERE id=$1 FOR UPDATE", id).Scan(&b); err != nil {
		return r, err
	}
	if err = json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if r.Revision != expected {
		return r, errors.New("revision changed; inspect the current evidence before reviewing")
	}
	now := time.Now().UTC()
	r.Revision++
	r.ModifiedAt = now
	switch action {
	case "approve":
		r.Status = "published"
		r.WithdrawnAt = nil
	case "reject":
		r.Status = "rejected"
	case "withdraw":
		r.Status = "withdrawn"
		r.WithdrawnAt = &now
	default:
		return r, errors.New("unknown review action")
	}
	if classification != "" {
		r.Classification = classification
	}
	if err = r.Validate(); err != nil {
		return r, err
	}
	r.Reviews = append(r.Reviews, model.Review{Action: action, Reviewer: reviewer, Rationale: rationale, At: now, Revision: r.Revision})
	b, _ = json.Marshal(r)
	if _, err = tx.ExecContext(ctx, "UPDATE reports SET record=$2,updated_at=now() WHERE id=$1", r.ID, b); err != nil {
		return r, err
	}
	if err = saveRevision(ctx, tx, r); err != nil {
		return r, err
	}
	if r.Status == "published" {
		err = savePublic(ctx, tx, r)
	} else {
		reason := "Operator withdrew the finding"
		if r.Status == "rejected" {
			reason = "Operator rejected the finding or its replacement"
		}
		_, err = retractPublic(ctx, tx, r.ID, r.Revision, now, reviewer, reason)
	}
	if err != nil {
		return r, err
	}
	return r, tx.Commit()
}
func (s *Store) Records(ctx context.Context, public bool) ([]model.Record, error) {
	q := "SELECT record FROM reports ORDER BY id"
	if public {
		q = "SELECT record FROM public_records ORDER BY id"
	}
	rows, err := s.DB.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Record{}
	for rows.Next() {
		var b []byte
		var r model.Record
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) Get(ctx context.Context, id string) (model.Record, error) {
	var b []byte
	var r model.Record
	err := s.DB.QueryRowContext(ctx, "SELECT record FROM reports WHERE id=$1", id).Scan(&b)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(b, &r)
	return r, err
}
func (s *Store) History(ctx context.Context, id string) ([]model.Record, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT record FROM report_revisions WHERE id=$1 ORDER BY revision", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Record{}
	for rows.Next() {
		var b []byte
		var r model.Record
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) Source(ctx context.Context, name string) (model.SourceState, error) {
	var st model.SourceState
	st.Name = name
	var b []byte
	err := s.DB.QueryRowContext(ctx, "SELECT state FROM source_state WHERE name=$1", name).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(b, &st)
	return st, err
}
func (s *Store) SaveSource(ctx context.Context, st model.SourceState) error {
	b, _ := json.Marshal(st)
	_, err := s.DB.ExecContext(ctx, "INSERT INTO source_state(name,state) VALUES($1,$2) ON CONFLICT(name) DO UPDATE SET state=excluded.state", st.Name, b)
	return err
}
func (s *Store) Sources(ctx context.Context) ([]model.SourceState, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT state FROM source_state ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.SourceState{}
	for rows.Next() {
		var b []byte
		var st model.SourceState
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &st); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}
func (s *Store) Event(ctx context.Context, kind, detail string) error {
	_, e := s.DB.ExecContext(ctx, "INSERT INTO service_events(kind,detail) VALUES($1,$2)", kind, detail)
	return e
}

type Job struct {
	ID         int64           `json:"id"`
	Kind       string          `json:"kind"`
	Payload    json.RawMessage `json:"payload"`
	Attempts   int             `json:"attempts"`
	LeaseToken string          `json:"lease_token"`
	CreatedAt  time.Time       `json:"created_at"`
	Priority   int             `json:"priority"`
}

func (s *Store) Enqueue(ctx context.Context, kind, key string, payload any, priority int) error {
	b, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	_, e = s.DB.ExecContext(ctx, "INSERT INTO jobs(kind,dedup_key,payload,priority) VALUES($1,$2,$3,$4) ON CONFLICT(dedup_key) DO NOTHING", kind, key, b, priority)
	return e
}
func token() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func (s *Store) Claim(ctx context.Context, kind string, lease time.Duration) (*Job, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var j Job
	j.LeaseToken = token()
	if _, err = tx.ExecContext(ctx, "UPDATE jobs SET status='failed',finished_at=now(),last_error='retry limit reached after lease expiration' WHERE kind=$1 AND status='running' AND attempts>=5 AND lease_until<now()", kind); err != nil {
		return nil, err
	}
	err = tx.QueryRowContext(ctx, `UPDATE jobs SET status='running', attempts=attempts+1,lease_until=now()+$2::interval,lease_token=$3
 WHERE id=(SELECT id FROM jobs WHERE kind=$1 AND attempts<5 AND ((status='queued' AND available_at<=now()) OR (status='running' AND lease_until<now()))
 ORDER BY priority DESC,id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,kind,payload,attempts,created_at,priority`, kind, fmt.Sprintf("%f seconds", lease.Seconds()), j.LeaseToken).Scan(&j.ID, &j.Kind, &j.Payload, &j.Attempts, &j.CreatedAt, &j.Priority)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &j, nil
}
func (s *Store) Finish(ctx context.Context, j Job, result any, runErr error) error {
	b, e := json.Marshal(result)
	if e != nil {
		return e
	}
	status := "done"
	detail := ""
	if runErr != nil {
		status = "queued"
		if j.Attempts >= 5 {
			status = "failed"
		}
		detail = runErr.Error()
	}
	r, e := s.DB.ExecContext(ctx, `UPDATE jobs SET status=$3,result=$4,last_error=$5,lease_until=NULL,lease_token=NULL,
 available_at=now()+($6::integer * interval '1 minute'),finished_at=CASE WHEN $3 IN ('done','failed','skipped') THEN now() ELSE NULL END
 WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now()`, j.ID, j.LeaseToken, status, b, detail, j.Attempts*j.Attempts)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("job lease expired or superseded")
	}
	return nil
}
func (s *Store) Reserve(ctx context.Context, kind string, amount, limit int64) (bool, error) {
	var used int64
	// Cast the numeric parameters before SELECT/WHERE can infer them as text.
	err := s.DB.QueryRowContext(ctx, `INSERT INTO budgets(day,kind,used) SELECT (now() AT TIME ZONE 'UTC')::date,$1,$2::bigint WHERE $2::bigint<=$3::bigint
 ON CONFLICT(day,kind) DO UPDATE SET used=budgets.used+excluded.used WHERE budgets.used+excluded.used<=$3::bigint RETURNING used`, kind, amount, limit).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
func (s *Store) Defer(ctx context.Context, j Job, reason string) error {
	r, err := s.DB.ExecContext(ctx, `UPDATE jobs SET status='queued',attempts=greatest(0,attempts-1),available_at=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'+interval '1 day',lease_token=NULL,lease_until=NULL,last_error=$3 WHERE id=$1 AND lease_token=$2 AND lease_until>now()`, j.ID, j.LeaseToken, reason)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("job lease expired")
	}
	return nil
}
func (s *Store) Publication(ctx context.Context) (int64, []byte, []model.Record, error) {
	var seq int64
	var m, b []byte
	err := s.DB.QueryRowContext(ctx, "SELECT p.sequence,p.manifest,s.records FROM publications p JOIN feed_snapshots s ON s.hash=p.records_hash ORDER BY p.sequence DESC LIMIT 1").Scan(&seq, &m, &b)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, []model.Record{}, nil
	}
	if err != nil {
		return 0, nil, nil, err
	}
	var records []model.Record
	err = json.Unmarshal(b, &records)
	return seq, m, records, err
}
func (s *Store) NextSequence(ctx context.Context) (int64, error) {
	var seq int64
	err := s.DB.QueryRowContext(ctx, "SELECT nextval(pg_get_serial_sequence('publications','sequence'))").Scan(&seq)
	return seq, err
}
func (s *Store) SavePublication(ctx context.Context, seq int64, manifest []byte, records []model.Record) error {
	b, e := json.Marshal(records)
	if e != nil {
		return e
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	hash := model.Hash(b)
	if _, e = tx.ExecContext(ctx, "INSERT INTO feed_snapshots(hash,records) VALUES($1,$2) ON CONFLICT(hash) DO NOTHING", hash, b); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO publications(sequence,manifest,records_hash) VALUES($1,$2,$3)", seq, manifest, hash); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) CurrentSequence(ctx context.Context) (int64, error) {
	var seq int64
	err := s.DB.QueryRowContext(ctx, "SELECT coalesce(max(sequence),0) FROM publications").Scan(&seq)
	return seq, err
}
func (s *Store) Stats(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	rows, err := s.DB.QueryContext(ctx, "SELECT kind,status,count(*),coalesce(extract(epoch FROM now()-min(created_at)),0) FROM jobs GROUP BY kind,status")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []map[string]any{}
	for rows.Next() {
		var kind, status string
		var n int
		var age float64
		if err = rows.Scan(&kind, &status, &n, &age); err != nil {
			return nil, err
		}
		jobs = append(jobs, map[string]any{"kind": kind, "status": status, "count": n, "oldest_seconds": age})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	out["jobs"] = jobs
	var skipped int
	err = s.DB.QueryRowContext(ctx, "SELECT count(*) FROM jobs WHERE result->>'status'='skipped'").Scan(&skipped)
	out["skipped_artifacts"] = skipped
	if err != nil {
		return nil, err
	}
	budgetRows, err := s.DB.QueryContext(ctx, "SELECT kind,used FROM budgets WHERE day=(now() AT TIME ZONE 'UTC')::date ORDER BY kind")
	if err != nil {
		return nil, err
	}
	defer budgetRows.Close()
	budgets := map[string]int64{}
	for budgetRows.Next() {
		var kind string
		var used int64
		if err = budgetRows.Scan(&kind, &used); err != nil {
			return nil, err
		}
		budgets[kind] = used
	}
	if err = budgetRows.Err(); err != nil {
		return nil, err
	}
	out["daily_reservations"] = budgets
	return out, nil
}
