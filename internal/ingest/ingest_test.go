package ingest

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"zoli.dev/intel-feed/internal/config"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/internal/netfetch"
)

type memoryReports struct {
	states  map[string]model.SourceState
	records map[string]model.Record
	skips   []string
}

func newMemoryReports() *memoryReports {
	return &memoryReports{states: map[string]model.SourceState{}, records: map[string]model.Record{}}
}
func (s *memoryReports) Lock(_ context.Context, _ string, fn func() error) error { return fn() }
func (s *memoryReports) Source(_ context.Context, name string) (model.SourceState, error) {
	v := s.states[name]
	v.Name = name
	v.Gaps = append([]string(nil), v.Gaps...)
	return v, nil
}
func (s *memoryReports) SaveSource(_ context.Context, v model.SourceState) error {
	s.states[v.Name] = v
	return nil
}
func (s *memoryReports) Ingest(_ context.Context, r model.Record, _ bool) error {
	if err := r.Validate(); err != nil {
		return err
	}
	s.records[r.ID] = r
	return nil
}
func (s *memoryReports) Get(_ context.Context, id string) (model.Record, error) {
	r, ok := s.records[id]
	if !ok {
		return r, sql.ErrNoRows
	}
	return r, nil
}
func (s *memoryReports) Records(context.Context, bool) ([]model.Record, error) {
	var out []model.Record
	for _, r := range s.records {
		out = append(out, r)
	}
	return out, nil
}
func (s *memoryReports) Event(_ context.Context, kind, detail string) error {
	if kind != "ingest_skip" {
		return fmt.Errorf("unexpected event %s", kind)
	}
	s.skips = append(s.skips, detail)
	return nil
}

type memoryHTTP func(*http.Request) (*http.Response, error)

func (f memoryHTTP) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func fixtureClient(fn func(*http.Request) (string, http.Header, error)) *netfetch.Client {
	return &netfetch.Client{Hosts: map[string]bool{"api.github.com": true, "storage.googleapis.com": true, "api.osv.dev": true}, HTTP: &http.Client{Transport: memoryHTTP(func(r *http.Request) (*http.Response, error) {
		b, h, err := fn(r)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(b))}, nil
	})}}
}

func ghsa(id, name, updated string) string {
	return fmt.Sprintf(`{"ghsa_id":%q,"type":"malware","summary":"Malicious package","updated_at":%q,"vulnerabilities":[{"package":{"ecosystem":"npm","name":%q},"vulnerable_version_range":"=1.0.0"}]}`, id, updated, name)
}

func TestGitHubUnsupportedReportContinuesPaginationAndCheckpoint(t *testing.T) {
	s := newMemoryReports()
	source := config.Source{Name: "github", Type: "github", URL: "https://api.github.com/advisories", License: "CC-BY-4.0", Trusted: true}
	stamp := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	bad := ghsa("GHSA-qqfx-rpxc-ghp4", "--hiljson", stamp)
	client := fixtureClient(func(r *http.Request) (string, http.Header, error) {
		if r.URL.Query().Get("page") == "" && r.URL.Query().Get("direction") != "desc" {
			return "", nil, errors.New("bootstrap must prioritize recent advisories")
		}
		if r.URL.Query().Get("is_withdrawn") == "true" {
			return "[]", nil, nil
		}
		if r.URL.Query().Get("page") == "2" {
			return "[" + ghsa("GHSA-later", "later-package", stamp) + "]", nil, nil
		}
		return "[" + ghsa("GHSA-first", "first-package", stamp) + "," + bad + "]", http.Header{"Link": {`<https://api.github.com/advisories?type=malware&is_withdrawn=false&page=2>; rel="next"`}}, nil
	})
	p := Pipeline{Store: s, Client: client, Dir: t.TempDir()}
	if err := p.RunSource(context.Background(), source, false); err != nil {
		t.Fatal(err)
	}
	st := s.states[source.Name]
	if len(s.records) != 2 || st.Cursor != stamp || st.LastSuccess == nil || st.Error != "" || len(st.Gaps) != 1 || len(s.skips) != 1 {
		t.Fatalf("records=%d state=%+v skips=%v", len(s.records), st, s.skips)
	}
	if !strings.Contains(st.Gaps[0], "GHSA-qqfx-rpxc-ghp4") {
		t.Fatal(st.Gaps)
	}
	if _, err := os.Stat(filepath.Join(p.Dir, "raw", model.Hash([]byte(bad))+".json")); err != nil {
		t.Fatal("skipped original not retained", err)
	}
	if err := p.RunSource(context.Background(), source, false); err != nil {
		t.Fatal(err)
	}
	if len(s.records) != 2 || len(s.states[source.Name].Gaps) != 1 {
		t.Fatal("replay duplicated records or coverage gaps")
	}
}

func TestMalformedReportPreservesSourceCheckpoint(t *testing.T) {
	s := newMemoryReports()
	stamp := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	s.states["github"] = model.SourceState{Name: "github", Cursor: stamp}
	source := config.Source{Name: "github", Type: "github", URL: "https://api.github.com/advisories", License: "CC-BY-4.0", Trusted: true}
	p := Pipeline{Store: s, Dir: t.TempDir(), Client: fixtureClient(func(*http.Request) (string, http.Header, error) {
		return `[{"type":"malware","updated_at":"2026-10-22T00:00:00Z","vulnerabilities":[{"package":{"ecosystem":"npm","name":"example"}}]}]`, nil, nil
	})}
	if err := p.RunSource(context.Background(), source, false); err == nil {
		t.Fatal("malformed report was hidden as a skip")
	}
	st := s.states[source.Name]
	if st.Cursor != stamp || st.LastSuccess != nil || st.Error == "" || len(s.skips) != 0 {
		t.Fatal(st, s.skips)
	}
}

func TestOSVBootstrapSkipsHistoricalUnsupportedName(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for _, row := range []struct{ name, body string }{
		{"MAL-2022-2.json", `{"id":"MAL-2022-2","summary":"Malicious code in --hiljson (npm)","affected":[{"package":{"ecosystem":"npm","name":"--hiljson"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`},
		{"MAL-2026-supported.json", `{"id":"MAL-2026-supported","summary":"Malicious package","affected":[{"package":{"ecosystem":"npm","name":"supported-package"},"versions":["2.0.0"]}]}`},
	} {
		f, err := zw.Create(row.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(f, row.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	s := newMemoryReports()
	source := config.Source{Name: "osv", Type: "osv", URL: "https://storage.googleapis.com/osv-vulnerabilities", Ecosystems: []string{"npm"}, License: "Apache-2.0", Trusted: true}
	p := Pipeline{Store: s, Dir: t.TempDir(), Client: fixtureClient(func(*http.Request) (string, http.Header, error) { return archive.String(), nil, nil })}
	if err := p.RunSource(context.Background(), source, false); err != nil {
		t.Fatal(err)
	}
	st := s.states[source.Name]
	if len(s.records) != 1 || st.Cursor == "" || st.LastSuccess == nil || st.LastAttempt == nil || st.LastSuccess.Before(*st.LastAttempt) || st.Error != "" || len(st.Gaps) != 1 {
		t.Fatalf("records=%d state=%+v", len(s.records), st)
	}
}

func TestWithdrawalWithoutPackageDataRetractsPriorIdentity(t *testing.T) {
	for _, kind := range []string{"github", "osv"} {
		t.Run(kind, func(t *testing.T) {
			s := newMemoryReports()
			source := config.Source{Name: kind, Type: kind, License: "Apache-2.0", Trusted: true}
			upstreamID := "MAL-2026-withdrawn"
			body := `{"id":"MAL-2026-withdrawn","withdrawn":"2026-10-22T01:00:00Z"}`
			if kind == "github" {
				upstreamID = "GHSA-withdrawn"
				body = `{"ghsa_id":"GHSA-withdrawn","type":"malware","withdrawn_at":"2026-10-22T01:00:00Z"}`
			}
			id := model.StableID(kind, upstreamID)
			s.records[id] = model.Record{ID: id, Affected: []model.Affected{{Package: model.Identity{Ecosystem: "npm", Name: "previous-package"}, Scope: "versions", Versions: []string{"1.0.0"}}}}
			p := Pipeline{Store: s, Dir: t.TempDir()}
			var gaps []string
			if err := p.save(context.Background(), source, []byte(body), &gaps); err != nil {
				t.Fatal(err)
			}
			r := s.records[id]
			if r.WithdrawnAt == nil || len(r.Affected) != 1 || r.Affected[0].Package.Name != "previous-package" || r.Affected[0].Versions[0] != "1.0.0" {
				t.Fatal(r)
			}
			delete(s.records, id)
			if err := p.save(context.Background(), source, []byte(body), &gaps); err != nil {
				t.Fatal(err)
			}
			if len(s.records) != 0 {
				t.Fatal("invented an identity for an unknown withdrawal")
			}
		})
	}
}

func TestOSVIncrementalFindsPackageLessWithdrawals(t *testing.T) {
	s := newMemoryReports()
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Minute)
	source := config.Source{Name: "osv", Type: "osv", URL: "https://storage.googleapis.com/osv-vulnerabilities", Ecosystems: []string{"npm"}, License: "Apache-2.0", Trusted: true}
	s.states[source.Name] = model.SourceState{Name: source.Name, Cursor: now.Add(-time.Hour).Format(time.RFC3339Nano)}
	id := model.StableID(source.Name, "MAL-2026-withdrawn")
	s.records[id] = model.Record{ID: id, Affected: []model.Affected{{Package: model.Identity{Ecosystem: "npm", Name: "previous-package"}, Versions: []string{"1.0.0"}, Scope: "versions"}}}
	readEmpty := false
	p := Pipeline{Store: s, Dir: t.TempDir(), Client: fixtureClient(func(r *http.Request) (string, http.Header, error) {
		switch r.URL.Path {
		case "/osv-vulnerabilities/npm/modified_id.csv":
			return "", nil, nil
		case "/osv-vulnerabilities/[EMPTY]/modified_id.csv":
			readEmpty = true
			return now.Format(time.RFC3339Nano) + ",MAL-2026-withdrawn\n", nil, nil
		case "/v1/vulns/MAL-2026-withdrawn":
			return `{"id":"MAL-2026-withdrawn","withdrawn":"2026-10-22T01:00:00Z"}`, nil, nil
		default:
			return "", nil, fmt.Errorf("unexpected request %s", r.URL)
		}
	})}
	if err := p.RunSource(ctx, source, false); err != nil {
		t.Fatal(err)
	}
	if !readEmpty || s.records[id].WithdrawnAt == nil || s.states[source.Name].LastSuccess == nil {
		t.Fatal("withdrawal was not applied during incremental polling")
	}
}

func TestUnsupportedReportIsNotAnIngestibleRecord(t *testing.T) {
	for _, row := range []struct{ kind, body string }{
		{"github", ghsa("GHSA-qqfx-rpxc-ghp4", "--hiljson", "2022-12-07T23:30:57Z")},
		{"osv", `{"id":"MAL-2022-2","summary":"Malicious package","affected":[{"package":{"ecosystem":"npm","name":"--hiljson"}}]}`},
	} {
		source := config.Source{Name: row.kind, Type: row.kind, License: "Apache-2.0", Trusted: true}
		parse := ParseOSV
		if row.kind == "github" {
			parse = ParseGitHub
		}
		r, auto, err := parse([]byte(row.body), source)
		var unsupported *unsupportedReport
		if !errors.As(err, &unsupported) || r.ID != "" || auto {
			t.Fatal(r, auto, err)
		}
	}
}
