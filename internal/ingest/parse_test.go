package ingest

import (
	"testing"
	"zoli.dev/intel-feed/internal/config"
)

func TestOrdinaryVulnerabilitiesExcluded(t *testing.T) {
	s := config.Source{Name: "source", License: "Apache-2.0", Trusted: true}
	r, _, err := ParseOSV([]byte(`{"id":"CVE-2026-1"}`), s)
	if err != nil || r.ID != "" {
		t.Fatal(r, err)
	}
	r, _, err = ParseGitHub([]byte(`{"ghsa_id":"GHSA-example","type":"reviewed"}`), s)
	if err != nil || r.ID != "" {
		t.Fatal(r, err)
	}
}
func TestBorderlineOSVNeedsReview(t *testing.T) {
	s := config.Source{Name: "source", License: "Apache-2.0", Trusted: true}
	r, auto, err := ParseOSV([]byte(`{"id":"MAL-2026-1","summary":"Empty package used in typosquatting research","affected":[{"package":{"ecosystem":"PyPI","name":"some_package"},"versions":["1.0"]}]}`), s)
	if err != nil {
		t.Fatal(err)
	}
	if auto || r.Classification != "suspicious" || r.Affected[0].Package.Name != "some-package" {
		t.Fatal(r, auto)
	}
}
func TestMissingVersionScopePreserved(t *testing.T) {
	s := config.Source{Name: "source", License: "Apache-2.0", Trusted: true}
	r, _, err := ParseOSV([]byte(`{"id":"MAL-2026-1","summary":"Malicious package","affected":[{"package":{"ecosystem":"npm","name":"example"}}]}`), s)
	if err != nil {
		t.Fatal(err)
	}
	if r.Affected[0].Scope != "unknown" {
		t.Fatal("widened unknown versions")
	}
}
