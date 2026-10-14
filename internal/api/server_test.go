package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"zoli.dev/intel-feed/internal/feed"
	"zoli.dev/intel-feed/internal/model"
)

func TestNoMatchIsNotSafeAndStalenessIsVisible(t *testing.T) {
	m := feed.Manifest{Sequence: 1, GeneratedAt: time.Now(), Coverage: model.DefaultCoverage()}
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
