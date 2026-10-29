package netfetch

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

type rateLimitHTTP func(*http.Request) (*http.Response, error)

func (f rateLimitHTTP) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGitHubRateLimitIsActionableAndDoesNotRetryImmediately(t *testing.T) {
	calls := 0
	c := New([]string{"api.github.com"}, "")
	c.HTTP.Transport = rateLimitHTTP(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 403, Header: http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {"1792679154"}}, Body: io.NopCloser(strings.NewReader("rate limited"))}, nil
	})
	_, err := c.Get(context.Background(), "https://api.github.com/advisories", 1024, "")
	if err == nil || !strings.Contains(err.Error(), "GitHub API token") || !strings.Contains(err.Error(), "2026-") || calls != 1 {
		t.Fatal(calls, err)
	}
}

func TestDestinationPolicy(t *testing.T) {
	c := New([]string{"pypi.org"}, "")
	for _, u := range []string{"http://pypi.org/data", "https://pypi.org:8443/data", "https://user:password@pypi.org/data", "https://127.0.0.1/data", "https://pypi.org.evil.example/data"} {
		if c.CheckURL(u) == nil {
			t.Fatal("accepted", u)
		}
	}
	if c.CheckURL("https://pypi.org/data") != nil {
		t.Fatal("rejected registry")
	}
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.1.1", "::1", "fc00::1"} {
		if publicIP(net.ParseIP(s)) {
			t.Fatal("accepted private address", s)
		}
	}
}
