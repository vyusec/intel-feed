// SPDX-License-Identifier: Apache-2.0
package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"zoli.dev/intel-feed/internal/analysis"
	"zoli.dev/intel-feed/internal/config"
	"zoli.dev/intel-feed/internal/feed"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/internal/store"
)

type QueryResponse struct {
	Status      string         `json:"status"`
	Matches     []model.Match  `json:"matches"`
	Sequence    int64          `json:"sequence"`
	GeneratedAt time.Time      `json:"generated_at"`
	Coverage    model.Coverage `json:"coverage"`
	Freshness   string         `json:"freshness"`
}
type Server struct {
	Store         *store.Store
	Config        config.Config
	OperatorToken string
	RunnerToken   string
	APIKeys       []string
	Trigger       func(context.Context) error
	limiter       limiter
	cacheMu       sync.Mutex
	cached        *publication
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := s.Store.DB.PingContext(ctx); err != nil {
			writeError(w, 503, "database unavailable")
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("GET /feed/latest.json", s.manifest)
	mux.HandleFunc("GET /feed/{path...}", s.artifact)
	mux.Handle("POST /v1/query", s.limit(http.HandlerFunc(s.query)))
	mux.Handle("POST /v1/querybatch", s.limit(http.HandlerFunc(s.queryBatch)))
	mux.Handle("GET /admin/reports", s.authorize(s.OperatorToken, http.HandlerFunc(s.reports)))
	mux.Handle("GET /admin/reports/{id}", s.authorize(s.OperatorToken, http.HandlerFunc(s.report)))
	mux.Handle("GET /admin/reports/{id}/history", s.authorize(s.OperatorToken, http.HandlerFunc(s.history)))
	mux.Handle("GET /admin/raw/{hash}", s.authorize(s.OperatorToken, http.HandlerFunc(s.raw)))
	mux.Handle("POST /admin/import", s.authorize(s.OperatorToken, http.HandlerFunc(s.importRecord)))
	mux.Handle("POST /admin/review", s.authorize(s.OperatorToken, http.HandlerFunc(s.review)))
	mux.Handle("POST /admin/ingest", s.authorize(s.OperatorToken, http.HandlerFunc(s.ingest)))
	mux.Handle("GET /admin/stats", s.authorize(s.OperatorToken, http.HandlerFunc(s.stats)))
	mux.Handle("POST /internal/runner/claim", s.authorize(s.RunnerToken, http.HandlerFunc(s.claim)))
	mux.Handle("POST /internal/runner/result", s.authorize(s.RunnerToken, http.HandlerFunc(s.runtimeResult)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		writeError(w, 400, "invalid JSON request")
		return false
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		writeError(w, 400, "one JSON value required")
		return false
	}
	return true
}
func equal(a, b string) bool {
	return len(a) >= 32 && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func (s *Server) authorize(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !equal(token, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
			writeError(w, 401, "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type bucket struct {
	window int64
	n      int
}
type limiter struct {
	mu     sync.Mutex
	byPeer map[string]bucket
}

func (s *Server) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		key := r.RemoteAddr
		if len(s.APIKeys) > 0 {
			ok := false
			for _, k := range s.APIKeys {
				if equal(k, token) {
					ok = true
					break
				}
			}
			if !ok {
				writeError(w, 401, "API key required")
				return
			}
			key = model.Hash([]byte(token))
		} else {
			if i := strings.LastIndex(key, ":"); i >= 0 {
				key = key[:i]
			}
		}
		window := time.Now().Unix() / 60
		s.limiter.mu.Lock()
		if s.limiter.byPeer == nil {
			s.limiter.byPeer = map[string]bucket{}
		}
		if len(s.limiter.byPeer) >= 10000 {
			for k, b := range s.limiter.byPeer {
				if b.window != window {
					delete(s.limiter.byPeer, k)
				}
			}
		}
		if _, known := s.limiter.byPeer[key]; !known && len(s.limiter.byPeer) >= 10000 {
			s.limiter.mu.Unlock()
			writeError(w, 429, "rate limit capacity reached")
			return
		}
		b := s.limiter.byPeer[key]
		if b.window != window {
			b = bucket{window: window}
		}
		b.n++
		s.limiter.byPeer[key] = b
		s.limiter.mu.Unlock()
		if b.n > s.Config.API.RequestsPerMinute {
			w.Header().Set("Retry-After", "60")
			writeError(w, 429, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type publication struct {
	manifest feed.Manifest
	records  []model.Record
	envelope []byte
	index    map[string][]model.Record
}

func (s *Server) view(ctx context.Context) (*publication, error) {
	seq, err := s.Store.CurrentSequence(ctx)
	if err != nil {
		return nil, err
	}
	if seq == 0 {
		return nil, errors.New("no published feed")
	}
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if s.cached != nil && s.cached.manifest.Sequence == seq {
		return s.cached, nil
	}
	_, b, records, err := s.Store.Publication(ctx)
	if err != nil {
		return nil, err
	}
	var env feed.Envelope
	var m feed.Manifest
	if err = json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(env.Manifest, &m); err != nil {
		return nil, err
	}
	s.cached = &publication{m, records, b, BuildIndex(records)}
	return s.cached, nil
}
func (s *Server) snapshot(ctx context.Context) (feed.Manifest, []model.Record, error) {
	v, err := s.view(ctx)
	if err != nil {
		return feed.Manifest{}, nil, err
	}
	return v.manifest, v.records, nil
}
func BuildIndex(records []model.Record) map[string][]model.Record {
	index := map[string][]model.Record{}
	for _, r := range records {
		seen := map[string]bool{}
		for _, a := range r.Affected {
			key := a.Package.Ecosystem + ":" + a.Package.Name
			if !seen[key] {
				index[key] = append(index[key], r)
				seen[key] = true
			}
		}
	}
	return index
}
func Query(q model.Identity, m feed.Manifest, records []model.Record) (QueryResponse, error) {
	out := QueryResponse{Status: "no_known_match", Sequence: m.Sequence, GeneratedAt: m.GeneratedAt, Matches: []model.Match{}, Freshness: "current"}
	if err := q.Normalize(); err != nil {
		return out, err
	}
	for _, c := range m.Coverage {
		if c.Ecosystem == q.Ecosystem {
			out.Coverage = c
		}
	}
	if time.Since(m.GeneratedAt) > time.Hour {
		out.Freshness = "stale"
	}
	for _, s := range m.Sources {
		if s.LastSuccess == nil || time.Since(*s.LastSuccess) > time.Hour || s.Error != "" {
			out.Freshness = "degraded"
		}
	}
	for _, r := range records {
		if r.Status != "published" || r.WithdrawnAt != nil {
			continue
		}
		best := "none"
		reasons := []string{}
		for _, a := range r.Affected {
			certainty, why := model.MatchAffected(q, a)
			if certainty == "exact" {
				best = "exact"
				reasons = nil
				break
			}
			if certainty == "range" {
				best = "range"
				reasons = nil
			} else if certainty == "uncertain" && best == "none" {
				best = certainty
				reasons = why
			}
		}
		if best != "none" {
			out.Matches = append(out.Matches, model.Match{Record: r, Certainty: best, Reasons: reasons})
			if best == "exact" || best == "range" {
				out.Status = "known_match"
			} else if out.Status != "known_match" {
				out.Status = "insufficient_information"
			}
		}
	}
	if out.Status == "no_known_match" && (q.Version == "" || out.Freshness != "current" || (q.Ecosystem == "Conda" && (q.Channel == "" || q.Subdir == "" || q.Build == ""))) {
		out.Status = "insufficient_information"
	}
	return out, nil
}
func (s *Server) query(w http.ResponseWriter, r *http.Request) {
	var q model.Identity
	if !decode(w, r, &q) {
		return
	}
	if err := q.Normalize(); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	v, err := s.view(r.Context())
	if err != nil {
		writeError(w, 503, "feed unavailable")
		return
	}
	out, err := Query(q, v.manifest, v.index[q.Ecosystem+":"+q.Name])
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) queryBatch(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Packages []model.Identity `json:"packages"`
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.Packages) == 0 || len(input.Packages) > 100 {
		writeError(w, 400, "batch must contain 1–100 packages")
		return
	}
	for i := range input.Packages {
		if err := input.Packages[i].Normalize(); err != nil {
			writeError(w, 400, err.Error())
			return
		}
	}
	v, err := s.view(r.Context())
	if err != nil {
		writeError(w, 503, "feed unavailable")
		return
	}
	out := []QueryResponse{}
	for _, q := range input.Packages {
		result, err := Query(q, v.manifest, v.index[q.Ecosystem+":"+q.Name])
		if err != nil {
			writeError(w, 400, err.Error())
			return
		}
		out = append(out, result)
	}
	writeJSON(w, 200, map[string]any{"results": out})
}
func (s *Server) manifest(w http.ResponseWriter, r *http.Request) {
	v, err := s.view(r.Context())
	if err != nil {
		writeError(w, 503, "feed unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, v.manifest.Sequence))
	w.Write(v.envelope)
}
func (s *Server) artifact(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	m, _, err := s.snapshot(r.Context())
	if err != nil {
		writeError(w, 503, "feed unavailable")
		return
	}
	allowed := false
	for _, a := range m.Files {
		if a.Path == path {
			allowed = true
			break
		}
	}
	if !allowed {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("Content-Type", "application/gzip")
	http.ServeFile(w, r, filepath.Join(s.Config.FeedDir, filepath.FromSlash(path)))
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	sources, err := s.Store.Sources(r.Context())
	if err != nil {
		writeError(w, 503, "status unavailable")
		return
	}
	seq, _, _, err := s.Store.Publication(r.Context())
	if err != nil {
		writeError(w, 503, "status unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"sequence": seq, "sources": sources, "coverage": model.DefaultCoverage()})
}
func (s *Server) reports(w http.ResponseWriter, r *http.Request) {
	records, err := s.Store.Records(r.Context(), false)
	if err != nil {
		writeError(w, 500, "reports unavailable")
		return
	}
	out := []model.Record{}
	for _, v := range records {
		if r.URL.Query().Get("status") != "" && v.Status != r.URL.Query().Get("status") {
			continue
		}
		if v.ID <= r.URL.Query().Get("after") {
			continue
		}
		out = append(out, v)
		if len(out) == 100 {
			break
		}
	}
	writeJSON(w, 200, map[string]any{"records": out})
}
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeError(w, 500, "report unavailable")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.History(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, 500, "history unavailable")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) raw(w http.ResponseWriter, r *http.Request) {
	h := r.PathValue("hash")
	if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(filepath.Join(s.Config.StorageDir, "raw", h+".json"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}
func (s *Server) review(w http.ResponseWriter, r *http.Request) {
	var v struct {
		ID             string `json:"id"`
		Action         string `json:"action"`
		Reviewer       string `json:"reviewer"`
		Rationale      string `json:"rationale"`
		Classification string `json:"classification,omitempty"`
		Revision       int    `json:"revision"`
	}
	if !decode(w, r, &v) {
		return
	}
	record, err := s.Store.Review(r.Context(), v.ID, v.Action, v.Reviewer, v.Rationale, v.Classification, v.Revision)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, record)
}
func (s *Server) importRecord(w http.ResponseWriter, r *http.Request) {
	var record model.Record
	if !decode(w, r, &record) {
		return
	}
	if err := s.Store.Ingest(r.Context(), record, false); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"id": record.ID, "status": "pending"})
}
func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	if s.Trigger == nil {
		writeError(w, 503, "scheduler unavailable")
		return
	}
	if err := s.Trigger(r.Context()); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "queued"})
}
func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.Stats(r.Context())
	if err != nil {
		writeError(w, 500, "stats unavailable")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	if !s.Config.Analysis.RuntimeEnabled {
		writeError(w, 503, "runtime analysis disabled")
		return
	}
	var j *store.Job
	err := s.Store.Lock(r.Context(), "runtime-claim", func() error {
		var err error
		var running int
		if err = s.Store.DB.QueryRowContext(r.Context(), "SELECT count(*) FROM jobs WHERE kind='runtime' AND status='running' AND lease_until>now()").Scan(&running); err != nil {
			return err
		}
		if running >= s.Config.Analysis.RuntimeConcurrency {
			return nil
		}
		j, err = s.Store.Claim(r.Context(), "runtime", s.Config.Analysis.RuntimeTimeout+5*time.Minute)
		if err != nil || j == nil {
			return err
		}
		ok, err := s.Store.Reserve(r.Context(), "runtime_jobs", 1, int64(s.Config.Analysis.DailyRuntimeJobs))
		if err != nil {
			return err
		}
		if !ok {
			err = s.Store.Defer(r.Context(), *j, "runtime budget exhausted")
			j = nil
		}
		return err
	})
	if err != nil {
		writeError(w, 503, "runner queue unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"job": j})
}
func (s *Server) runtimeResult(w http.ResponseWriter, r *http.Request) {
	var result analysis.RuntimeResult
	if !decode(w, r, &result) {
		return
	}
	var payload []byte
	var attempts int
	err := s.Store.DB.QueryRowContext(r.Context(), "SELECT payload,attempts FROM jobs WHERE id=$1 AND lease_token=$2 AND status='running' AND kind='runtime' AND lease_until>now()", result.JobID, result.LeaseToken).Scan(&payload, &attempts)
	if err != nil {
		writeError(w, 409, "runtime lease invalid")
		return
	}
	var expected analysis.Artifact
	if json.Unmarshal(payload, &expected) != nil || expected.SHA256 != result.Artifact.SHA256 || !model.SamePackage(expected.Package, result.Artifact.Package) || expected.Package.Version != result.Artifact.Package.Version || expected.URL != result.Artifact.URL || expected.Filename != result.Artifact.Filename {
		writeError(w, 400, "runtime artifact identity mismatch")
		return
	}
	if len(result.Evidence) > 20 || len(result.Limitations) > 100 {
		writeError(w, 400, "runtime evidence limits exceeded")
		return
	}
	err = s.Store.CompleteRuntime(r.Context(), store.Job{ID: result.JobID, LeaseToken: result.LeaseToken, Attempts: attempts}, result)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "recorded_for_review"})
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
