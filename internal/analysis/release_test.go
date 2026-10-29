package analysis

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"zoli.dev/intel-feed/internal/discovery"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/internal/netfetch"
)

type releaseHTTP func(*http.Request) (*http.Response, error)

func (f releaseHTTP) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAnalysisResolvesExactDiscoveredRelease(t *testing.T) {
	for _, ecosystem := range []string{"npm", "PyPI"} {
		t.Run(ecosystem, func(t *testing.T) {
			version := "20.0.0-beta.1"
			wantPath := "/example/" + version
			body := fmt.Sprintf(`{"name":"example","version":%q,"dist":{"tarball":"https://registry.npmjs.org/example/-/example.tgz","integrity":%q}}`, version, "sha512-"+base64.StdEncoding.EncodeToString(make([]byte, 64)))
			if ecosystem == "PyPI" {
				version = "3.0.0rc1"
				wantPath = "/pypi/example/" + version + "/json"
				body = fmt.Sprintf(`{"urls":[{"url":"https://files.pythonhosted.org/example.tar.gz","filename":"example.tar.gz","digests":{"sha256":%q}}]}`, strings.Repeat("a", 64))
			}
			calls := 0
			client := &netfetch.Client{Hosts: map[string]bool{"registry.npmjs.org": true, "pypi.org": true, "files.pythonhosted.org": true}, HTTP: &http.Client{Transport: releaseHTTP(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != wantPath {
					return nil, fmt.Errorf("resolved a different release: %s", r.URL.Path)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			w := Worker{Client: client}
			artifacts, err := w.Resolve(context.Background(), discovery.Release{Package: model.Identity{Ecosystem: ecosystem, Name: "example", Version: version}})
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || len(artifacts) != 1 || artifacts[0].Package.Version != version {
				t.Fatal(calls, artifacts)
			}
		})
	}
}
