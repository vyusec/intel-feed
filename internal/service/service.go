// SPDX-License-Identifier: Apache-2.0
package service

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"zoli.dev/intel-feed/internal/analysis"
	"zoli.dev/intel-feed/internal/api"
	"zoli.dev/intel-feed/internal/config"
	"zoli.dev/intel-feed/internal/discovery"
	"zoli.dev/intel-feed/internal/feed"
	"zoli.dev/intel-feed/internal/ingest"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/internal/netfetch"
	"zoli.dev/intel-feed/internal/store"
)

type Service struct {
	Config    config.Config
	Store     *store.Store
	Ingest    *ingest.Pipeline
	Discovery *discovery.Discovery
	Worker    *analysis.Worker
	Publisher *feed.Publisher
	trigger   chan struct{}
}

func New(ctx context.Context, c config.Config) (*Service, error) {
	s, err := store.Open(ctx, os.Getenv(c.DatabaseEnv))
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			s.DB.Close()
		}
	}()
	if err = s.Migrate(ctx); err != nil {
		return nil, err
	}
	rules, err := analysis.LoadRules(c.RulesFile)
	if err != nil {
		return nil, err
	}
	key, err := feed.ReadKey(c.SigningKey)
	if err != nil {
		return nil, err
	}
	hosts := []string{"storage.googleapis.com", "api.osv.dev", "api.github.com"}
	hosts = append(hosts, sourceHosts(c.Sources)...)
	p := &ingest.Pipeline{Store: s, Client: netfetch.New(hosts, os.Getenv(c.GitHubTokenEnv)), Dir: c.StorageDir, Sources: c.Sources}
	for _, source := range c.Sources {
		state, err := s.Source(ctx, source.Name)
		if err != nil {
			return nil, err
		}
		if state.Coverage == "" {
			state.Coverage = "published_malware_reports"
			if err = s.SaveSource(ctx, state); err != nil {
				return nil, err
			}
		}
	}
	w := &analysis.Worker{Store: s, Client: netfetch.New([]string{"registry.npmjs.org", "pypi.org", "files.pythonhosted.org"}, ""), Config: c.Analysis, Rules: rules, Dir: c.StorageDir}
	d, err := discovery.New(s, c.Analysis.Watchlist, c.Analysis.ProtectedPackages)
	if err != nil {
		return nil, err
	}
	coverage := model.DefaultCoverage()
	for i := range coverage {
		if !c.Analysis.Enabled {
			coverage[i].Mode = "reports_only"
		}
		if coverage[i].Ecosystem == "npm" || coverage[i].Ecosystem == "PyPI" {
			if !c.Analysis.RuntimeEnabled {
				coverage[i].Limitations = append(coverage[i].Limitations, "Runtime analysis disabled")
			}
		}
	}
	out := &Service{Config: c, Store: s, Ingest: p, Discovery: d, Worker: w, Publisher: &feed.Publisher{Store: s, Dir: c.FeedDir, Key: key, RuleSetSHA256: rules.Hash, Coverage: coverage}, trigger: make(chan struct{}, 1)}
	cleanup = false
	return out, nil
}
func sourceHosts(ss []config.Source) []string {
	out := []string{}
	for _, s := range ss {
		out = append(out, netfetch.Hosts(s.URL)...)
	}
	return out
}
func (s *Service) Run(ctx context.Context) error {
	op := os.Getenv(s.Config.OperatorTokenEnv)
	runner := os.Getenv(s.Config.RunnerTokenEnv)
	if len(op) < 32 || strings.HasPrefix(op, "replace-") {
		return errors.New("operator token must be at least 32 characters")
	}
	if s.Config.Analysis.RuntimeEnabled && (len(runner) < 32 || runner == op) {
		return errors.New("runner token must be at least 32 characters and differ from operator token")
	}
	keys := []string{}
	for _, key := range strings.Split(os.Getenv(s.Config.API.KeysEnv), ",") {
		if key != "" {
			if len(key) < 32 {
				return errors.New("API keys must be at least 32 characters")
			}
			keys = append(keys, key)
		}
	}
	a := &api.Server{Store: s.Store, Config: s.Config, OperatorToken: op, RunnerToken: runner, APIKeys: keys, Trigger: func(context.Context) error {
		select {
		case s.trigger <- struct{}{}:
			return nil
		default:
			return errors.New("ingestion already queued")
		}
	}}
	h := &http.Server{Addr: s.Config.Listen, Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	start := func(fn func(context.Context)) { wg.Add(1); go func() { defer wg.Done(); fn(child) }() }
	start(s.importLoop)
	if s.Config.Analysis.Enabled {
		start(func(ctx context.Context) { periodic(ctx, s.Config.DiscoveryInterval, true, s.Discovery.Run) })
	}
	start(func(ctx context.Context) { periodic(ctx, s.Config.PublishInterval, true, s.Publisher.Publish) })
	go func() {
		<-child.Done()
		stopCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		h.Shutdown(stopCtx)
	}()
	err := h.ListenAndServe()
	cancel()
	wg.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func (s *Service) importLoop(ctx context.Context) {
	timer := time.NewTicker(s.Config.IngestInterval)
	defer timer.Stop()
	daily := time.NewTicker(24 * time.Hour)
	defer daily.Stop()
	run := func(reconcile bool) {
		for _, source := range s.Config.Sources {
			if err := s.Ingest.RunSource(ctx, source, reconcile); err != nil && !errors.Is(err, store.ErrLocked) {
				slog.Error("source ingestion failed", "source", source.Name, "error", err)
			}
		}
	}
	run(false)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			run(false)
		case <-s.trigger:
			run(false)
		case <-daily.C:
			run(true)
		}
	}
}
func periodic(ctx context.Context, d time.Duration, initial bool, fn func(context.Context) error) {
	run := func() {
		if err := fn(ctx); err != nil && !errors.Is(err, store.ErrLocked) && !errors.Is(err, context.Canceled) {
			slog.Error("scheduled operation failed", "error", err)
		}
	}
	if initial {
		run()
	}
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
