// SPDX-License-Identifier: Apache-2.0
package model

import (
	"deps.dev/util/semver"
	"errors"
	"fmt"
	"strings"
)

func system(e string) (semver.System, error) {
	switch e {
	case "npm":
		return semver.NPM, nil
	case "PyPI":
		return semver.PyPI, nil
	case "Cargo":
		return semver.Cargo, nil
	case "Maven":
		return semver.Maven, nil
	}
	return 0, errors.New("unsupported version comparison")
}
func Compare(ecosystem, a, b string) (int, error) {
	s, err := system(ecosystem)
	if err != nil {
		return 0, err
	}
	av, err := s.Parse(a)
	if err != nil {
		return 0, err
	}
	bv, err := s.Parse(b)
	if err != nil {
		return 0, err
	}
	if av.IsWildcard() || bv.IsWildcard() {
		return 0, errors.New("expected concrete versions")
	}
	return av.Compare(bv), nil
}

type Match struct {
	Record    Record   `json:"record"`
	Certainty string   `json:"certainty"`
	Reasons   []string `json:"reasons,omitempty"`
}

// MatchAffected returns none, exact, range or uncertain; missing selectors never widen a finding.
func MatchAffected(q Identity, a Affected) (string, []string) {
	p := a.Package
	if q.Ecosystem != p.Ecosystem || q.Name != p.Name {
		return "none", nil
	}
	reasons := []string{}
	for _, v := range [][3]string{{"registry", p.Registry, q.Registry}, {"sha256", p.SHA256, q.SHA256}, {"channel", p.Channel, q.Channel}, {"subdir", p.Subdir, q.Subdir}, {"build", p.Build, q.Build}} {
		if v[1] != "" && v[2] != "" && v[1] != v[2] {
			return "none", nil
		}
		if v[1] != "" && v[2] == "" {
			reasons = append(reasons, "missing "+v[0])
		}
	}
	if q.Ecosystem == "Conda" && (p.Channel == "" || p.Subdir == "" || p.Build == "") {
		reasons = append(reasons, "report lacks Conda artifact selectors")
	}
	if q.Version == "" {
		return "uncertain", append(reasons, "missing version")
	}
	certainty := "none"
	unknown := false
	if a.Scope == "all" {
		certainty = "range"
	}
	if a.Scope == "unknown" {
		unknown = true
	}
	versions := a.Versions
	if p.Version != "" {
		versions = append(append([]string{}, versions...), p.Version)
	}
	for _, v := range versions {
		if q.Version == v {
			certainty = "exact"
			break
		}
		c, err := Compare(q.Ecosystem, q.Version, v)
		if err != nil {
			unknown = true
			continue
		}
		if c == 0 {
			certainty = "exact"
			break
		}
	}
	for _, r := range a.Ranges {
		matched, err := matchRange(q, r)
		if err != nil {
			unknown = true
			reasons = append(reasons, err.Error())
		} else if matched && certainty != "exact" {
			certainty = "range"
		}
	}
	if len(versions) == 0 && len(a.Ranges) == 0 && a.Scope != "all" {
		unknown = true
	}
	if certainty == "none" && unknown {
		certainty = "uncertain"
	}
	if certainty != "none" && len(reasons) > 0 {
		certainty = "uncertain"
	}
	return certainty, reasons
}
func matchRange(q Identity, r Range) (bool, error) {
	s, err := system(q.Ecosystem)
	if err != nil {
		return false, err
	}
	v, err := s.Parse(q.Version)
	if err != nil || v.IsWildcard() {
		return false, errors.New("invalid query version")
	}
	if r.Type == "constraint" {
		c, err := s.ParseConstraint(r.Constraint)
		if err != nil {
			return false, fmt.Errorf("unsupported version constraint: %s", r.Constraint)
		}
		return c.MatchVersion(v), nil
	}
	if r.Type != "ECOSYSTEM" && r.Type != "SEMVER" {
		return false, errors.New("unsupported range type: " + r.Type)
	}
	if len(r.Events) == 0 {
		return false, errors.New("empty range events")
	}
	active := false
	matched := false
	open := false
	for _, e := range r.Events {
		n := 0
		for _, x := range []string{e.Introduced, e.Fixed, e.LastAffected, e.Limit} {
			if x != "" {
				n++
			}
		}
		if n != 1 {
			return false, errors.New("invalid range event")
		}
		if e.Introduced != "" {
			if open {
				return false, errors.New("nested introduced event")
			}
			open = true
			if e.Introduced == "0" {
				active = true
			} else {
				c, err := Compare(q.Ecosystem, q.Version, e.Introduced)
				if err != nil {
					return false, err
				}
				active = c >= 0
			}
			continue
		}
		if !open {
			return false, errors.New("range end without introduced event")
		}
		end := e.Fixed
		if end == "" {
			end = e.Limit
		}
		inclusive := false
		if end == "" {
			end = e.LastAffected
			inclusive = true
		}
		c, err := Compare(q.Ecosystem, q.Version, end)
		if err != nil {
			return false, err
		}
		if active && (c < 0 || (inclusive && c == 0)) {
			matched = true
		}
		active = false
		open = false
	}
	return matched || active, nil
}
func SamePackage(a, b Identity) bool {
	return a.Ecosystem == b.Ecosystem && a.Name == b.Name && strings.TrimRight(a.Registry, "/") == strings.TrimRight(b.Registry, "/")
}
