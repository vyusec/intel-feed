package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ossf/package-feeds/pkg/feeds"
	"strings"
	"sync"
	"testing"
	"time"
	"zoli.dev/intel-feed/internal/model"
)

type memoryReleases struct {
	mu          sync.Mutex
	states      map[string]model.SourceState
	jobs        map[string]Release
	priorities  map[string]int
	failVersion string
}

func newMemoryReleases() *memoryReleases {
	return &memoryReleases{states: map[string]model.SourceState{}, jobs: map[string]Release{}, priorities: map[string]int{}}
}
func (s *memoryReleases) Lock(_ context.Context, _ string, fn func() error) error { return fn() }
func (s *memoryReleases) Source(_ context.Context, name string) (model.SourceState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.states[name]
	v.Name = name
	v.Gaps = append([]string(nil), v.Gaps...)
	return v, nil
}
func (s *memoryReleases) SaveSource(_ context.Context, v model.SourceState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[v.Name] = v
	return nil
}
func (s *memoryReleases) Event(context.Context, string, string) error { return nil }
func (s *memoryReleases) Enqueue(_ context.Context, kind, key string, payload any, priority int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if kind != "static" {
		return errors.New("wrong job kind")
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var rel Release
	if err = json.Unmarshal(b, &rel); err != nil {
		return err
	}
	if rel.Package.Version == s.failVersion {
		return errors.New("queue unavailable")
	}
	s.jobs[key] = rel
	s.priorities[key] = priority
	return nil
}

type fixtureFeed struct {
	name   string
	latest func(time.Time) ([]*feeds.Package, time.Time, []error)
}

func (f fixtureFeed) GetName() string                   { return f.name }
func (f fixtureFeed) GetFeedOptions() feeds.FeedOptions { return feeds.FeedOptions{} }
func (f fixtureFeed) Latest(cutoff time.Time) ([]*feeds.Package, time.Time, []error) {
	return f.latest(cutoff)
}

func TestProtectedPackagesHaveNormalizedRecoveryWatchlists(t *testing.T) {
	d, err := New(nil, map[string][]string{"PyPI": {"Some_Package"}}, map[string][]string{"pypi": {"some-package", "Requests"}, "npm": {"react"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Feeds) != 4 {
		t.Fatal("missing recovery feeds", len(d.Feeds))
	}
	for _, f := range d.Feeds[2:] {
		options := f.GetFeedOptions()
		if options.Packages == nil {
			t.Fatal("recovery feed is not configured for individual packages")
		}
		if f.GetName() == "pypi:watchlist" && strings.Join(*options.Packages, ",") != "requests,some-package" {
			t.Fatal(*options.Packages)
		}
	}
}

func TestDiscoveryInitialStateReplayAndQueueFailure(t *testing.T) {
	s := newMemoryReleases()
	now := time.Now().UTC()
	old := now.Add(-time.Hour).Format(time.RFC3339Nano)
	s.states["registry:npm"] = model.SourceState{Name: "registry:npm", Cursor: old}
	f := fixtureFeed{name: "npm", latest: func(cutoff time.Time) ([]*feeds.Package, time.Time, []error) {
		if !cutoff.Before(now.Add(-time.Hour)) {
			t.Fatal("poll did not overlap previous checkpoint")
		}
		return []*feeds.Package{feeds.NewPackage(now, "react", "20.0.0-beta.1", "npm"), feeds.NewPackage(now, "other", "2.0.0", "npm")}, now, nil
	}}
	d := Discovery{Store: s, Feeds: []feeds.ScheduledFeed{f}, Watchlist: map[string][]string{"npm": {"react"}}}
	if err := d.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.states["registry:npm"].LastSuccess != nil || s.states["registry:npm"].Coverage == "" {
		t.Fatal("first poll was falsely marked complete")
	}
	s.failVersion = "2.0.0"
	if err := d.Run(context.Background()); err == nil {
		t.Fatal("partial queue failure was hidden")
	}
	if st := s.states["registry:npm"]; st.Cursor != old || st.LastSuccess != nil || st.Error == "" {
		t.Fatal(st)
	}
	s.failVersion = ""
	if err := d.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := s.states["registry:npm"]
	if len(s.jobs) != 2 || st.Cursor != now.Format(time.RFC3339Nano) || st.LastSuccess == nil || st.Error != "" {
		t.Fatal(s.jobs, st)
	}
	for key, rel := range s.jobs {
		if rel.Package.Name == "react" && (rel.Package.Version != "20.0.0-beta.1" || s.priorities[key] != 100) {
			t.Fatal("exact new release or watchlist priority lost", rel)
		}
	}
}

func TestInvalidReleaseDoesNotAdvanceCheckpoint(t *testing.T) {
	for _, pkg := range []*feeds.Package{feeds.NewPackage(time.Now(), "example", "", "npm"), feeds.NewPackage(time.Time{}, "example", "1.0.0", "npm")} {
		s := newMemoryReleases()
		d := Discovery{Store: s, Feeds: []feeds.ScheduledFeed{fixtureFeed{name: "npm", latest: func(t time.Time) ([]*feeds.Package, time.Time, []error) {
			return []*feeds.Package{pkg}, time.Now(), nil
		}}}}
		if err := d.Run(context.Background()); err == nil {
			t.Fatal("invalid release accepted")
		}
		if len(s.jobs) != 0 || s.states["registry:npm"].Cursor != "" {
			t.Fatal(s.jobs, s.states)
		}
	}
}

func TestSlowRegistryDoesNotBlockOtherRegistryPoll(t *testing.T) {
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	fastPolled := make(chan struct{})
	done := make(chan error, 1)
	d := Discovery{Store: newMemoryReleases(), Feeds: []feeds.ScheduledFeed{
		fixtureFeed{name: "npm", latest: func(cutoff time.Time) ([]*feeds.Package, time.Time, []error) {
			close(slowStarted)
			<-releaseSlow
			return nil, cutoff, nil
		}},
		fixtureFeed{name: "pypi", latest: func(cutoff time.Time) ([]*feeds.Package, time.Time, []error) {
			close(fastPolled)
			return nil, cutoff, nil
		}},
	}}
	go func() { done <- d.Run(context.Background()) }()
	t.Cleanup(func() {
		close(releaseSlow)
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("registry polls did not finish")
		}
	})
	select {
	case <-slowStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("slow poll did not start")
	}
	select {
	case <-fastPolled:
	case <-time.After(2 * time.Second):
		t.Fatal("PyPI poll waited for npm")
	}
}
