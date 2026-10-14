package model

import (
	"testing"
	"time"
)

func TestIdentityNormalization(t *testing.T) {
	for _, c := range []struct{ ecosystem, name, wantEc, wantName string }{{"pip", "Some_Package.Name", "PyPI", "some-package-name"}, {"Poetry", "requests", "PyPI", "requests"}, {"pnpm", "@team/tool", "npm", "@team/tool"}, {"Maven", "org.example:tool", "Maven", "org.example:tool"}, {"crates", "my_crate", "Cargo", "my_crate"}} {
		p := Identity{Ecosystem: c.ecosystem, Name: c.name}
		if err := p.Normalize(); err != nil {
			t.Fatal(err)
		}
		if p.Ecosystem != c.wantEc || p.Name != c.wantName {
			t.Fatalf("%+v", p)
		}
	}
	for _, p := range []Identity{{Ecosystem: "npm", Name: "../bad"}, {Ecosystem: "PyPI", Name: "good", Registry: "https://user:password@example.com"}, {Ecosystem: "Maven", Name: "artifact"}, {Ecosystem: "npm", Name: "UPPERCASE"}} {
		if err := p.Normalize(); err == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
}
func TestVersionMatching(t *testing.T) {
	for _, c := range []struct {
		ec, version string
		affected    Affected
		want        string
	}{
		{"npm", "1.0.0", Affected{Scope: "versions", Versions: []string{"1.0.0"}}, "exact"},
		{"npm", "1.0.1", Affected{Scope: "versions", Versions: []string{"1.0.0"}}, "none"},
		{"PyPI", "1.0rc1", Affected{Scope: "versions", Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "1.0rc1"}, {Fixed: "1.0"}}}}}, "range"},
		{"PyPI", "1.0", Affected{Scope: "versions", Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "1.0rc1"}, {Fixed: "1.0"}}}}}, "none"},
		{"Cargo", "1.1.0", Affected{Scope: "versions", Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {LastAffected: "1.1.0"}}}}}, "range"},
		{"npm", "2.0.0", Affected{Scope: "versions", Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "1.0.0"}, {Fixed: "1.1.0"}, {Introduced: "3.0.0"}}}}}, "none"},
		{"Maven", "1.5", Affected{Scope: "versions", Ranges: []Range{{Type: "constraint", Constraint: "[1.0,2.0)"}}}, "range"},
		{"Maven", "2.0", Affected{Scope: "versions", Ranges: []Range{{Type: "constraint", Constraint: "[1.0,2.0)"}}}, "none"},
		{"Conda", "1.0", Affected{Scope: "versions", Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}}}}}, "uncertain"},
		{"npm", "1.0.0", Affected{Scope: "unknown"}, "uncertain"},
		{"npm", "", Affected{Scope: "all"}, "uncertain"},
	} {
		q := Identity{Ecosystem: c.ec, Name: "example", Version: c.version}
		if c.ec == "Maven" {
			q.Name = "org.example:tool"
		}
		if err := q.Normalize(); err != nil {
			t.Fatal(err)
		}
		a := c.affected
		a.Package = q
		a.Package.Version = ""
		if c.ec == "Conda" {
			a.Package.Channel = "conda-forge"
			a.Package.Subdir = "linux-64"
			a.Package.Build = "py_0"
		}
		got, _ := MatchAffected(q, a)
		if got != c.want {
			t.Errorf("%s %s got %s want %s", c.ec, c.version, got, c.want)
		}
	}
}
func TestArtifactSelectorsNeverWiden(t *testing.T) {
	p := Identity{Ecosystem: "Conda", Name: "tool", Version: "1.0", Channel: "conda-forge", Subdir: "linux-64", Build: "py_0", SHA256: Hash([]byte("artifact"))}
	a := Affected{Package: p, Scope: "versions", Versions: []string{"1.0"}}
	q := p
	q.SHA256 = ""
	if got, _ := MatchAffected(q, a); got != "uncertain" {
		t.Fatal(got)
	}
	q = p
	q.Build = "py_1"
	if got, _ := MatchAffected(q, a); got != "none" {
		t.Fatal(got)
	}
	q = p
	if got, _ := MatchAffected(q, a); got != "exact" {
		t.Fatal(got)
	}
}
func TestMalformedRangeIsUncertain(t *testing.T) {
	q := Identity{Ecosystem: "npm", Name: "tool", Version: "1.0.0"}
	a := Affected{Package: Identity{Ecosystem: "npm", Name: "tool"}, Scope: "versions", Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Fixed: "1.1.0"}}}}}
	if got, _ := MatchAffected(q, a); got != "uncertain" {
		t.Fatal(got)
	}
}
func TestContentHashDoesNotMutateProvenance(t *testing.T) {
	r := Record{Sources: []Provenance{{RetrievedAt: time.Now()}}}
	before := r.Sources[0].RetrievedAt
	r.ContentHash()
	if !r.Sources[0].RetrievedAt.Equal(before) {
		t.Fatal("hash mutated input")
	}
}
