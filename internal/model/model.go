// SPDX-License-Identifier: Apache-2.0
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const Schema = "1.0"

var Ecosystems = []string{"PyPI", "npm", "Cargo", "Maven", "Conda"}

type Identity struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Registry  string `json:"registry,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Channel   string `json:"channel,omitempty"`
	Subdir    string `json:"subdir,omitempty"`
	Build     string `json:"build,omitempty"`
}
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}
type Range struct {
	Type       string  `json:"type"`
	Constraint string  `json:"constraint,omitempty"`
	Events     []Event `json:"events,omitempty"`
}
type Affected struct {
	Package  Identity `json:"package"`
	Versions []string `json:"versions,omitempty"`
	Ranges   []Range  `json:"ranges,omitempty"`
	Scope    string   `json:"scope"` // versions, all, or unknown. Empty input becomes unknown.
}
type Provenance struct {
	Source      string    `json:"source"`
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	License     string    `json:"license"`
	Revision    string    `json:"revision"`
	RetrievedAt time.Time `json:"retrieved_at"`
}
type Evidence struct {
	RuleID         string   `json:"rule_id,omitempty"`
	RuleVersion    string   `json:"rule_version,omitempty"`
	ArtifactSHA256 string   `json:"artifact_sha256,omitempty"`
	File           string   `json:"file,omitempty"`
	Line           int      `json:"line,omitempty"`
	Explanation    string   `json:"explanation"`
	Observations   []string `json:"observations,omitempty"`
	Reproduce      string   `json:"reproduce,omitempty"`
	Limitations    []string `json:"limitations,omitempty"`
}
type Review struct {
	Action    string    `json:"action"`
	Reviewer  string    `json:"reviewer"`
	Rationale string    `json:"rationale"`
	At        time.Time `json:"at"`
	Revision  int       `json:"revision"`
}
type Record struct {
	SchemaVersion   string       `json:"schema_version"`
	ID              string       `json:"id"`
	Aliases         []string     `json:"aliases,omitempty"`
	Classification  string       `json:"classification"`
	Status          string       `json:"status"`
	Summary         string       `json:"summary"`
	Affected        []Affected   `json:"affected"`
	Evidence        []Evidence   `json:"evidence"`
	Sources         []Provenance `json:"sources"`
	References      []string     `json:"references,omitempty"`
	PublishedAt     time.Time    `json:"published_at,omitempty"`
	ModifiedAt      time.Time    `json:"modified_at"`
	WithdrawnAt     *time.Time   `json:"withdrawn_at,omitempty"`
	Revision        int          `json:"revision"`
	Reviews         []Review     `json:"reviews,omitempty"`
	OriginalLicense string       `json:"original_license,omitempty"`
}
type SourceState struct {
	Name        string     `json:"name"`
	Cursor      string     `json:"cursor,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
	Error       string     `json:"error,omitempty"`
	Coverage    string     `json:"coverage"`
	Gaps        []string   `json:"gaps,omitempty"`
}
type Coverage struct {
	Ecosystem   string   `json:"ecosystem"`
	Mode        string   `json:"mode"`
	Limitations []string `json:"limitations"`
}

func DefaultCoverage() []Coverage {
	out := []Coverage{}
	for _, e := range Ecosystems {
		mode := "reports_only"
		if e == "npm" || e == "PyPI" {
			mode = "reports_and_selective_analysis"
		}
		limits := []string{"No known match is not proof of safety", "Public reports are incomplete"}
		if e == "Conda" {
			limits = append(limits, "No enabled registry analysis; exact channel/build selectors required", "Version ranges are preserved but not evaluated")
		}
		if e == "npm" || e == "PyPI" {
			limits = append(limits, "Release feeds may omit events; gaps are reported", "Analysis is bounded by configured budgets")
		}
		out = append(out, Coverage{e, mode, limits})
	}
	return out
}
func Hash(b []byte) string              { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func StableID(source, id string) string { return "ZOLI-" + Hash([]byte(source + ":" + id))[:24] }

var pypiSeparators = regexp.MustCompile(`[-_.]+`)
var simpleName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
var npmName = regexp.MustCompile(`^(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*$`)

func (p *Identity) Normalize() error {
	switch strings.ToLower(p.Ecosystem) {
	case "pypi", "pip", "poetry", "pipenv":
		p.Ecosystem = "PyPI"
		p.Name = pypiSeparators.ReplaceAllString(strings.ToLower(p.Name), "-")
	case "npm", "pnpm":
		p.Ecosystem = "npm"
	case "cargo", "crates", "rust":
		p.Ecosystem = "Cargo"
		p.Name = strings.ToLower(p.Name)
	case "maven":
		p.Ecosystem = "Maven"
	case "conda":
		p.Ecosystem = "Conda"
		p.Name = strings.ToLower(p.Name)
	default:
		return errors.New("unsupported ecosystem")
	}
	if len(p.Name) > 214 || len(p.Version) > 200 {
		return errors.New("package identity too long")
	}
	valid := simpleName.MatchString(p.Name)
	if p.Ecosystem == "npm" {
		valid = npmName.MatchString(p.Name)
	}
	if p.Ecosystem == "Maven" {
		s := strings.Split(p.Name, ":")
		valid = len(s) == 2 && simpleName.MatchString(s[0]) && simpleName.MatchString(s[1])
	}
	if !valid {
		return fmt.Errorf("invalid %s package name", p.Ecosystem)
	}
	defaults := map[string]string{"PyPI": "https://pypi.org", "npm": "https://registry.npmjs.org", "Cargo": "https://crates.io", "Maven": "https://repo.maven.apache.org/maven2"}
	if p.Registry == "" {
		p.Registry = defaults[p.Ecosystem]
	}
	if p.Ecosystem == "PyPI" && strings.TrimRight(p.Registry, "/") == "https://pypi.org/simple" {
		p.Registry = "https://pypi.org"
	}
	if p.Ecosystem == "Cargo" {
		switch strings.TrimRight(p.Registry, "/") {
		case "https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io", "https://index.crates.io":
			p.Registry = "https://crates.io"
		}
	}
	if p.Registry != "" {
		u, err := url.Parse(p.Registry)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("registry must be an HTTPS base URL without credentials")
		}
		u.Host = strings.ToLower(u.Host)
		p.Registry = strings.TrimRight(u.String(), "/")
	}
	if p.SHA256 != "" {
		p.SHA256 = strings.ToLower(p.SHA256)
		b, e := hex.DecodeString(p.SHA256)
		if e != nil || len(b) != 32 {
			return errors.New("sha256 must contain 64 hex characters")
		}
	}
	return nil
}
func (r *Record) Validate() error {
	if r.SchemaVersion == "" {
		r.SchemaVersion = Schema
	}
	if r.SchemaVersion != Schema {
		return errors.New("unsupported schema version")
	}
	if r.ID == "" || len(r.ID) > 100 || len(r.Affected) == 0 || len(r.Sources) == 0 {
		return errors.New("id, affected packages and provenance are required")
	}
	if r.Classification != "malicious" && r.Classification != "suspicious" {
		return errors.New("classification must be malicious or suspicious")
	}
	for i := range r.Affected {
		a := &r.Affected[i]
		if err := a.Package.Normalize(); err != nil {
			return err
		}
		if a.Scope == "" {
			a.Scope = "unknown"
		}
		if a.Scope != "unknown" && a.Scope != "versions" && a.Scope != "all" {
			return errors.New("invalid affected scope")
		}
		if a.Scope == "all" && (len(a.Versions) > 0 || len(a.Ranges) > 0 || a.Package.Version != "") {
			return errors.New("all scope cannot contain version selectors")
		}
	}
	for _, s := range r.Sources {
		if s.Source == "" || s.ID == "" || s.License == "" || s.Revision == "" {
			return errors.New("complete source attribution is required")
		}
	}
	if len(r.Evidence) == 0 {
		return errors.New("evidence is required")
	}
	for _, e := range r.Evidence {
		if strings.TrimSpace(e.Explanation) == "" {
			return errors.New("evidence explanation is required")
		}
		if (e.RuleID == "") != (e.RuleVersion == "") {
			return errors.New("rule id and version must be provided together")
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(b) > 1<<20 {
		return errors.New("intelligence record exceeds size limit")
	}
	return nil
}

// ContentHash excludes ingestion and operator metadata so replay preserves approvals.
func (r Record) ContentHash() string {
	r.Reviews = nil
	r.Revision = 0
	r.Status = ""
	r.ModifiedAt = time.Time{}
	r.Sources = append([]Provenance{}, r.Sources...)
	for i := range r.Sources {
		r.Sources[i].RetrievedAt = time.Time{}
	}
	b, _ := json.Marshal(r)
	return Hash(b)
}
