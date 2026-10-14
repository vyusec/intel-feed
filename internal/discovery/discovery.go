// SPDX-License-Identifier: Apache-2.0
package discovery

import (
	"context"
	"errors"
	"fmt"
	"github.com/ossf/package-feeds/pkg/events"
	"github.com/ossf/package-feeds/pkg/feeds"
	"github.com/ossf/package-feeds/pkg/feeds/npm"
	"github.com/ossf/package-feeds/pkg/feeds/pypi"
	"io"
	"net/http"
	"strings"
	"time"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/internal/netfetch"
	"zoli.dev/intel-feed/internal/store"
)

type Release struct {
	Package     model.Identity `json:"package"`
	PublishedAt time.Time      `json:"published_at"`
	ArtifactID  string         `json:"artifact_id,omitempty"`
	Signals     []string       `json:"signals,omitempty"`
}
type Discovery struct {
	Store     *store.Store
	Feeds     []feeds.ScheduledFeed
	Watchlist map[string][]string
	Protected map[string][]string
}
type gapSink struct{ Store *store.Store }

func (s gapSink) AddEvent(e events.Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if loss, ok := e.(events.LossyFeedEvent); ok {
		name := "registry:" + loss.Feed
		st, err := s.Store.Source(ctx, name)
		if err != nil {
			return err
		}
		st.Gaps = appendGap(st.Gaps, e.GetMessage())
		if err = s.Store.SaveSource(ctx, st); err != nil {
			return err
		}
	}
	return s.Store.Event(ctx, "discovery_gap", e.GetMessage())
}
func appendGap(gaps []string, s string) []string {
	for _, g := range gaps {
		if g == s {
			return gaps
		}
	}
	if len(gaps) >= 20 {
		gaps = gaps[len(gaps)-19:]
	}
	return append(gaps, s)
}

type boundedTransport struct {
	Parent http.RoundTripper
	Max    int64
}

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := t.Parent.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	res.Body = &boundedBody{res.Body, t.Max}
	return res, nil
}

type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		var tmp [1]byte
		n, err := b.ReadCloser.Read(tmp[:])
		if n > 0 {
			return 0, errors.New("registry response size limit")
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}
func New(s *store.Store, watch, protected map[string][]string) (*Discovery, error) {
	c := netfetch.New([]string{"registry.npmjs.org", "pypi.org"}, "")
	c.HTTP.Transport = boundedTransport{c.HTTP.Transport, 16 << 20}
	c.HTTP.Timeout = 45 * time.Second
	h := events.NewHandler(gapSink{s}, events.Filter{EnabledEventTypes: []string{events.LossyFeedEventType}})
	n, err := npm.New(feeds.FeedOptions{}, h)
	if err != nil {
		return nil, err
	}
	n.SetClient(c.HTTP)
	pypi.SetClient(c.HTTP)
	p, err := pypi.New(feeds.FeedOptions{}, h)
	if err != nil {
		return nil, err
	}
	out := []feeds.ScheduledFeed{n, p}
	// Watchlists additionally recover versions omitted by the public rolling feeds.
	for e, pkgs := range watch {
		if len(pkgs) == 0 {
			continue
		}
		copy := append([]string{}, pkgs...)
		switch strings.ToLower(e) {
		case "npm":
			f, err := npm.New(feeds.FeedOptions{Packages: &copy}, h)
			if err != nil {
				return nil, err
			}
			f.SetClient(c.HTTP)
			out = append(out, watchFeed{f})
		case "pypi":
			f, err := pypi.New(feeds.FeedOptions{Packages: &copy}, h)
			if err != nil {
				return nil, err
			}
			out = append(out, watchFeed{f})
		}
	}
	return &Discovery{s, out, watch, protected}, nil
}

type watchFeed struct{ feeds.ScheduledFeed }

func (f watchFeed) GetName() string { return f.ScheduledFeed.GetName() + ":watchlist" }
func (d *Discovery) Run(ctx context.Context) error {
	var errs []error
	for _, f := range d.Feeds {
		if err := d.poll(ctx, f); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
func (d *Discovery) poll(ctx context.Context, f feeds.ScheduledFeed) error {
	return d.Store.Lock(ctx, "discovery:"+f.GetName(), func() error {
		name := "registry:" + f.GetName()
		st, err := d.Store.Source(ctx, name)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		st.LastAttempt = &now
		st.Coverage = "rolling_release_feed_with_selective_analysis"
		cutoff := now.Add(-10 * time.Minute)
		if st.Cursor != "" {
			cutoff, err = time.Parse(time.RFC3339Nano, st.Cursor)
			if err != nil {
				return err
			}
		}
		if st.LastSuccess != nil && now.Sub(*st.LastSuccess) > 20*time.Minute {
			st.Gaps = appendGap(st.Gaps, "Polling outage exceeded 20 minutes; rolling registry feed may omit releases")
		}
		pkgs, next, errs := f.Latest(cutoff.Add(-10 * time.Minute))
		actual := []error{}
		for _, e := range errs {
			if !errors.Is(e, feeds.ErrNoPackagesPolled) {
				actual = append(actual, e)
			}
		}
		for _, pkg := range pkgs {
			if err := ctx.Err(); err != nil {
				return err
			}
			id := model.Identity{Ecosystem: pkg.Type, Name: pkg.Name, Version: pkg.Version}
			if err = id.Normalize(); err != nil {
				actual = append(actual, err)
				continue
			}
			rel := Release{Package: id, PublishedAt: pkg.CreatedDate, ArtifactID: pkg.ArtifactID}
			priority := 0
			for _, n := range d.Watchlist[strings.ToLower(id.Ecosystem)] {
				if n == id.Name {
					priority = 100
					rel.Signals = append(rel.Signals, "watchlist")
				}
			}
			for _, n := range d.Protected[strings.ToLower(id.Ecosystem)] {
				if id.Name != n && editDistanceOne(id.Name, n) {
					priority += 10
					rel.Signals = append(rel.Signals, "name resembles protected package "+n)
				}
			}
			key := fmt.Sprintf("release:%s:%s:%s:%s", id.Ecosystem, id.Name, id.Version, pkg.ArtifactID)
			if err = d.Store.Enqueue(ctx, "static", key, rel, priority); err != nil {
				actual = append(actual, err)
			}
		}
		// Preserve the cursor on partial failure; already persisted events are idempotent.
		if len(actual) > 0 {
			st.Error = errors.Join(actual...).Error()
		} else {
			if next.Before(cutoff) {
				next = cutoff
			}
			st.Cursor = next.Format(time.RFC3339Nano)
			st.LastSuccess = &now
			st.Error = ""
		}
		// A sink may have recorded a loss event during Latest; don't overwrite it.
		fresh, err := d.Store.Source(ctx, name)
		if err != nil {
			return err
		}
		for _, g := range fresh.Gaps {
			st.Gaps = appendGap(st.Gaps, g)
		}
		if err = d.Store.SaveSource(ctx, st); err != nil {
			return err
		}
		return errors.Join(actual...)
	})
}
func editDistanceOne(a, b string) bool {
	if a == b || len(a) > len(b)+1 || len(b) > len(a)+1 {
		return false
	}
	i, j, n := 0, 0, 0
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
		n++
		if n > 1 {
			return false
		}
		if len(a) >= len(b) {
			i++
		}
		if len(b) >= len(a) {
			j++
		}
	}
	if i < len(a) || j < len(b) {
		n++
	}
	return n == 1
}
