package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"zoli.dev/intel-feed/internal/feed"
	"zoli.dev/intel-feed/internal/model"
)

func TestStatusCoverageMatchesPublishedManifest(t *testing.T) {
	manifest, err := json.Marshal(feed.Manifest{Coverage: []model.Coverage{{Ecosystem: "npm", Mode: "reports_only"}}})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(feed.Envelope{Manifest: manifest})
	if err != nil {
		t.Fatal(err)
	}
	coverage, err := statusCoverage(true, 2, envelope)
	if err != nil || len(coverage) != 1 || coverage[0].Mode != "reports_only" {
		t.Fatal(coverage, err)
	}
	coverage, err = statusCoverage(false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range coverage {
		if c.Mode != "reports_only" {
			t.Fatal("unpublished report-only service claimed analysis coverage", c)
		}
	}
	if _, err := statusCoverage(true, 2, []byte("broken")); err == nil {
		t.Fatal("corrupt publication reported healthy coverage")
	}
}

func TestNoMatchIsNotSafeAndStalenessIsVisible(t *testing.T) {
	now := time.Now().UTC()
	m := feed.Manifest{Sequence: 1, GeneratedAt: now, Coverage: model.DefaultCoverage(), Sources: []model.SourceState{{LastSuccess: &now}}}
	q := model.Identity{Ecosystem: "pip", Name: "requests", Version: "1.0"}
	out, err := Query(q, m, nil)
	if err != nil || out.Status != "no_known_match" {
		t.Fatal(out, err)
	}
	m.GeneratedAt = time.Now().Add(-2 * time.Hour)
	out, err = Query(q, m, nil)
	if err != nil || out.Status != "insufficient_information" || out.Freshness != "stale" {
		t.Fatal(out, err)
	}
}

func TestExactFreshnessBoundariesAndFutureClocks(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	q := model.Identity{Ecosystem: "npm", Name: "fixture", Version: "1.0.0"}
	for _, offset := range []time.Duration{-time.Hour - time.Nanosecond, -time.Hour, 0, 5 * time.Minute, 5*time.Minute + time.Nanosecond} {
		for _, source := range []bool{false, true} {
			stamp := now.Add(offset)
			m := feed.Manifest{GeneratedAt: now, Coverage: model.DefaultCoverage(), Sources: []model.SourceState{{LastSuccess: &now}}}
			if source {
				m.Sources[0].LastSuccess = &stamp
			} else {
				m.GeneratedAt = stamp
			}
			out, err := QueryAt(q, m, nil, now)
			if err != nil {
				t.Fatal(err)
			}
			current := offset >= -time.Hour && offset <= 5*time.Minute
			if (out.Freshness == "current") != current || (out.Status == "no_known_match") != current {
				t.Fatal(offset, source, out)
			}
		}
	}
	out, err := QueryAt(q, feed.Manifest{GeneratedAt: now, Coverage: model.DefaultCoverage()}, nil, now)
	if err != nil || out.Freshness != "degraded" || out.Status != "insufficient_information" {
		t.Fatal(out, err)
	}
}

func TestSourceFreshnessAndMissingVersionRemainVisible(t *testing.T) {
	now := time.Now().UTC()
	stale := now.Add(-2 * time.Hour)
	for _, tc := range []struct {
		name    string
		version string
		source  model.SourceState
		status  string
		fresh   string
	}{
		{"report_only_current", "1.0.0", model.SourceState{LastSuccess: &now}, "no_known_match", "current"},
		{"missing_version", "", model.SourceState{LastSuccess: &now}, "insufficient_information", "current"},
		{"bootstrap_incomplete", "1.0.0", model.SourceState{}, "insufficient_information", "degraded"},
		{"source_error", "1.0.0", model.SourceState{LastSuccess: &now, Error: "upstream unavailable"}, "insufficient_information", "degraded"},
		{"source_stale", "1.0.0", model.SourceState{LastSuccess: &stale}, "insufficient_information", "degraded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := feed.Manifest{Sequence: 1, GeneratedAt: now, Coverage: []model.Coverage{{Ecosystem: "npm", Mode: "reports_only"}}, Sources: []model.SourceState{tc.source}}
			out, err := Query(model.Identity{Ecosystem: "npm", Name: "fixture", Version: tc.version}, m, nil)
			if err != nil || out.Status != tc.status || out.Freshness != tc.fresh || out.Coverage.Mode != "reports_only" {
				t.Fatal(out, err)
			}
		})
	}
}
func TestLimiterCapacityRecoversAfterWindow(t *testing.T) {
	s := &Server{}
	s.Config.API.RequestsPerMinute = 60
	s.limiter.byPeer = map[string]bucket{}
	for i := 0; i < 10000; i++ {
		s.limiter.byPeer[fmt.Sprint(i)] = bucket{window: time.Now().Unix()/60 - 1, n: 1}
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	s.limit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })).ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal("old entries blocked new requests", w.Code)
	}
}
func TestUnauthorizedOperatorAndRunnerRejected(t *testing.T) {
	s := &Server{OperatorToken: strings.Repeat("o", 32), RunnerToken: strings.Repeat("r", 32)}
	for _, path := range []string{"/admin/reports", "/internal/runner/claim"} {
		method := "GET"
		if strings.Contains(path, "runner") {
			method = "POST"
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatal(w.Code)
		}
	}
}
func TestStrictJSONInput(t *testing.T) {
	for _, input := range []string{`{"name":"example"} trailing`, `{"name":"example"} {}`, `{"unknown":true}`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(input))
		var q model.Identity
		if decode(w, r, &q) {
			t.Fatal("accepted", input)
		}
	}
}
