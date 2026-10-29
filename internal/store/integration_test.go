package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
	"zoli.dev/intel-feed/internal/api"
	"zoli.dev/intel-feed/internal/config"
	"zoli.dev/intel-feed/internal/feed"
	"zoli.dev/intel-feed/internal/ingest"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/internal/netfetch"
	"zoli.dev/intel-feed/internal/store"
)

func isolated(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("ZOLI_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set ZOLI_TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 8)
	rand.Read(b)
	schema := "zoli_test_" + hex.EncodeToString(b)
	if _, err = admin.DB.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	s, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close(); admin.DB.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE"); admin.DB.Close() })
	return s
}
func sample() model.Record {
	return model.Record{SchemaVersion: model.Schema, ID: "ZOLI-test", Classification: "suspicious", Summary: "Controlled fixture", Affected: []model.Affected{{Package: model.Identity{Ecosystem: "npm", Name: "example"}, Versions: []string{"1.0.0"}, Scope: "versions"}}, Evidence: []model.Evidence{{Explanation: "Synthetic evidence"}}, Sources: []model.Provenance{{Source: "zoli", ID: "fixture", License: "CC-BY-4.0", Revision: "fixture-v1", URL: "https://example.invalid", RetrievedAt: time.Now().UTC()}}}
}
func TestReviewPublicationLookupAndWithdrawal(t *testing.T) {
	s := isolated(t)
	ctx := context.Background()
	r := sample()
	if err := s.Ingest(ctx, r, false); err != nil {
		t.Fatal(err)
	}
	stored, err := s.Get(ctx, r.ID)
	if err != nil || stored.Status != "pending" {
		t.Fatal(stored, err)
	}
	if _, err = s.Review(ctx, r.ID, "approve", "tester", "Fixture approval", "malicious", 1); err != nil {
		t.Fatal(err)
	}
	if err = s.Ingest(ctx, r, false); err != nil {
		t.Fatal(err)
	}
	stored, _ = s.Get(ctx, r.ID)
	if stored.Status != "published" || stored.Revision != 2 {
		t.Fatal("replay reset approval", stored)
	}
	if _, err = s.Review(ctx, r.ID, "withdraw", "tester", "stale review", "", 1); err == nil {
		t.Fatal("accepted stale review")
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	p := feed.Publisher{Store: s, Dir: t.TempDir(), Key: key, RuleSetSHA256: "rules-v1"}
	if err = p.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	seq, b, records, err := s.Publication(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var env feed.Envelope
	if err = json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	m, err := feed.Verify(env, key.Public().(ed25519.PublicKey), 0)
	if err != nil {
		t.Fatal("database corrupted signed bytes", err)
	}
	if m.Sequence != seq || feed.RecordsHash(records) != m.RecordsSHA256 {
		t.Fatal("snapshot mismatch")
	}
	server := api.Server{Store: s, Config: config.Default()}
	req := httptest.NewRequest("POST", "/v1/query", strings.NewReader(`{"ecosystem":"npm","name":"example","version":"1.0.0"}`))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var out api.QueryResponse
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Status != "known_match" || out.Sequence != seq {
		t.Fatal(out)
	}
	if err = p.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := s.CurrentSequence(ctx)
	if unchanged != seq {
		t.Fatal("unchanged publication created redundant release")
	}
	if _, err = s.Review(ctx, r.ID, "withdraw", "tester", "False positive corrected", "", 2); err != nil {
		t.Fatal(err)
	}
	if err = p.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	_, _, nowRecords, err := s.Publication(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deltas := feed.Diff(records, nowRecords)
	if len(deltas) != 1 || deltas[0].Operation != "withdraw" {
		t.Fatal(deltas)
	}
	replayed, err := feed.ApplyDelta(records, deltas)
	if err != nil || feed.RecordsHash(replayed) != feed.RecordsHash(nowRecords) {
		t.Fatal(err)
	}
}
func TestJobsLeasesBudgetsAndRuntimeOutbox(t *testing.T) {
	s := isolated(t)
	ctx := context.Background()
	if err := s.Enqueue(ctx, "runtime", "job", map[string]string{"package": "fixture"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(ctx, "runtime", "job", map[string]string{"package": "fixture"}, 0); err != nil {
		t.Fatal(err)
	}
	first, err := s.Claim(ctx, "runtime", time.Minute)
	if err != nil || first == nil {
		t.Fatal(first, err)
	}
	if other, err := s.Claim(ctx, "runtime", time.Minute); err != nil || other != nil {
		t.Fatal("duplicate claim", other, err)
	}
	if _, err = s.DB.ExecContext(ctx, "UPDATE jobs SET lease_until=now()-interval '1 second' WHERE id=$1", first.ID); err != nil {
		t.Fatal(err)
	}
	second, err := s.Claim(ctx, "runtime", time.Minute)
	if err != nil || second == nil || second.LeaseToken == first.LeaseToken {
		t.Fatal(second, err)
	}
	if err = s.CompleteRuntime(ctx, *first, map[string]string{"result": "stale"}); err == nil {
		t.Fatal("accepted superseded runtime output")
	}
	var count int
	s.DB.QueryRowContext(ctx, "SELECT count(*) FROM jobs WHERE kind='runtime-evidence'").Scan(&count)
	if count != 0 {
		t.Fatal("stale result entered outbox")
	}
	if err = s.CompleteRuntime(ctx, *second, map[string]string{"result": "current"}); err != nil {
		t.Fatal(err)
	}
	s.DB.QueryRowContext(ctx, "SELECT count(*) FROM jobs WHERE kind='runtime-evidence'").Scan(&count)
	if count != 1 {
		t.Fatal(count)
	}
	ok, err := s.Reserve(ctx, "bytes", 20, 30)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	ok, err = s.Reserve(ctx, "bytes", 20, 30)
	if err != nil || ok {
		t.Fatal("budget exceeded", ok, err)
	}
}
func TestPrivateReplacementNeverLeaksThroughWithdrawal(t *testing.T) {
	s := isolated(t)
	ctx := context.Background()
	r := sample()
	if err := s.Ingest(ctx, r, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Review(ctx, r.ID, "approve", "tester", "Approved fixture", "malicious", 1); err != nil {
		t.Fatal(err)
	}
	r.Evidence = []model.Evidence{{Explanation: "PRIVATE_REPLACEMENT_EVIDENCE"}}
	r.Sources[0].Revision = "fixture-v2"
	if err := s.Ingest(ctx, r, false); err != nil {
		t.Fatal(err)
	}
	current, _ := s.Get(ctx, r.ID)
	if _, err := s.Review(ctx, r.ID, "reject", "tester", "PRIVATE_REJECTION_RATIONALE", "", current.Revision); err != nil {
		t.Fatal(err)
	}
	public, err := s.Records(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(public)
	if strings.Contains(string(b), "PRIVATE_") {
		t.Fatal("private evidence leaked into tombstone")
	}
	private := sample()
	private.ID = "ZOLI-private"
	private.Sources[0].ID = "private"
	if err := s.Ingest(ctx, private, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Review(ctx, private.ID, "withdraw", "tester", "Private candidate discarded", "", 1); err != nil {
		t.Fatal(err)
	}
	public, _ = s.Records(ctx, true)
	if len(public) != 1 {
		t.Fatal("unpublished candidate appeared publicly")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSourceSkipsUnsupportedIdentityAndAppliesEmptyWithdrawal(t *testing.T) {
	s := isolated(t)
	ctx := context.Background()
	source := config.Source{Name: "github-live-regression", Type: "github", URL: "https://api.github.com/advisories", License: "CC-BY-4.0", Trusted: true}
	withdraw := false
	client := &netfetch.Client{Hosts: map[string]bool{"api.github.com": true}, HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		body := "[]"
		if !withdraw && r.URL.Query().Get("is_withdrawn") == "false" {
			body = `[{"ghsa_id":"GHSA-supported","type":"malware","summary":"Malicious package","updated_at":"2026-10-22T00:00:00Z","vulnerabilities":[{"package":{"ecosystem":"npm","name":"supported-package"},"vulnerable_version_range":"=1.0.0"}]},{"ghsa_id":"GHSA-qqfx-rpxc-ghp4","type":"malware","updated_at":"2026-10-22T00:00:00Z","vulnerabilities":[{"package":{"ecosystem":"npm","name":"--hiljson"}}]}]`
		} else if withdraw && r.URL.Query().Get("is_withdrawn") == "true" {
			body = `[{"ghsa_id":"GHSA-supported","type":"malware","updated_at":"2026-10-22T01:00:00Z","withdrawn_at":"2026-10-22T01:00:00Z"}]`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	p := ingest.Pipeline{Store: s, Client: client, Dir: t.TempDir()}
	if err := p.RunSource(ctx, source, false); err != nil {
		t.Fatal(err)
	}
	st, err := s.Source(ctx, source.Name)
	if err != nil || st.LastSuccess == nil || st.Error != "" || len(st.Gaps) != 1 {
		t.Fatal(st, err)
	}
	public, err := s.Records(ctx, true)
	if err != nil || len(public) != 1 || public[0].Status != "published" {
		t.Fatal(public, err)
	}
	withdraw = true
	if err := p.RunSource(ctx, source, false); err != nil {
		t.Fatal(err)
	}
	public, err = s.Records(ctx, true)
	if err != nil || len(public) != 1 || public[0].Status != "withdrawn" || public[0].Affected[0].Package.Name != "supported-package" {
		t.Fatal(public, err)
	}
}
func TestSourceCursorDoesNotAdvanceAfterPartialFailure(t *testing.T) {
	s := isolated(t)
	ctx := context.Background()
	now := time.Now().UTC()
	original := now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
	source := config.Source{Name: "github", Type: "github", URL: "https://api.github.com/advisories", License: "CC-BY-4.0", Trusted: true}
	if err := s.SaveSource(ctx, model.SourceState{Name: source.Name, Cursor: original}); err != nil {
		t.Fatal(err)
	}
	client := &netfetch.Client{Hosts: map[string]bool{"api.github.com": true}, HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		h := http.Header{}
		status := 200
		body := fmt.Sprintf(`[{"ghsa_id":"GHSA-fixture","type":"malware","summary":"Malicious package","updated_at":%q,"vulnerabilities":[{"package":{"ecosystem":"npm","name":"example"},"vulnerable_version_range":"=1.0.0"}]}]`, now.Format(time.RFC3339Nano))
		if r.URL.Query().Get("after") != "" {
			status = 503
			body = "{}"
			h.Set("Retry-After", "31")
		} else {
			h.Set("Link", `<https://api.github.com/advisories?type=malware&after=next>; rel="next"`)
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	p := ingest.Pipeline{Store: s, Client: client, Dir: t.TempDir()}
	if err := p.RunSource(ctx, source, false); err == nil {
		t.Fatal("expected source failure")
	}
	state, err := s.Source(ctx, source.Name)
	if err != nil || state.Cursor != original || state.Error == "" {
		t.Fatal(state, err)
	}
	records, err := s.Records(ctx, false)
	if err != nil || len(records) != 1 {
		t.Fatal("completed page not persisted", records, err)
	}
}

func TestConcurrentSourcesDoNotAutoPublishConflictingAliasScopes(t *testing.T) {
	s := isolated(t)
	ctx := context.Background()
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		r := sample()
		r.ID = fmt.Sprintf("ZOLI-concurrent-%d", i)
		r.Aliases = []string{"MAL-shared-alias"}
		r.Sources[0].Source = fmt.Sprintf("source-%d", i)
		r.Sources[0].ID = fmt.Sprintf("report-%d", i)
		r.Affected[0].Versions = []string{fmt.Sprintf("%d.0.0", i+1)}
		go func() {
			<-start
			results <- s.Ingest(ctx, r, true)
		}()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	public, err := s.Records(ctx, true)
	if err != nil || len(public) != 1 {
		t.Fatal("conflicting claims both published", public, err)
	}
	all, err := s.Records(ctx, false)
	if err != nil || len(all) != 2 {
		t.Fatal(all, err)
	}
	pending := 0
	for _, r := range all {
		if r.Status == "pending" {
			pending++
		}
	}
	if pending != 1 {
		t.Fatal("conflicting report must require review", all)
	}
}
