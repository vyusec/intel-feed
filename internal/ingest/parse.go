// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
	"zoli.dev/intel-feed/internal/config"
	"zoli.dev/intel-feed/internal/model"
)

type OSV struct {
	ID        string     `json:"id"`
	Aliases   []string   `json:"aliases"`
	Summary   string     `json:"summary"`
	Details   string     `json:"details"`
	Published time.Time  `json:"published"`
	Modified  time.Time  `json:"modified"`
	Withdrawn *time.Time `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Versions []string      `json:"versions"`
		Ranges   []model.Range `json:"ranges"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

func ParseOSV(b []byte, s config.Source) (model.Record, bool, error) {
	var o OSV
	var r model.Record
	if err := json.Unmarshal(b, &o); err != nil {
		return r, false, err
	}
	if !strings.HasPrefix(o.ID, "MAL-") {
		return r, false, nil
	}
	r = model.Record{SchemaVersion: model.Schema, ID: model.StableID(s.Name, o.ID), Aliases: append([]string{o.ID}, o.Aliases...), Classification: "malicious", Summary: o.Summary, PublishedAt: o.Published, WithdrawnAt: o.Withdrawn}
	for _, a := range o.Affected {
		ec := a.Package.Ecosystem
		if ec == "crates.io" {
			ec = "Cargo"
		}
		p := model.Identity{Ecosystem: ec, Name: a.Package.Name}
		if err := p.Normalize(); err != nil {
			continue
		}
		scope := "unknown"
		if len(a.Versions) > 0 || len(a.Ranges) > 0 {
			scope = "versions"
		}
		r.Affected = append(r.Affected, model.Affected{Package: p, Versions: a.Versions, Ranges: a.Ranges, Scope: scope})
	}
	for _, ref := range o.References {
		r.References = append(r.References, ref.URL)
	}
	r.Sources = []model.Provenance{{Source: s.Name, ID: o.ID, URL: "https://osv.dev/vulnerability/" + o.ID, License: s.License, Revision: model.Hash(b), RetrievedAt: time.Now().UTC()}}
	// Publish a summary of the evidence, retaining the complete upstream report privately.
	r.Evidence = []model.Evidence{{Explanation: "Upstream malicious-package report; inspect attributed references for original analysis", Limitations: []string{"Zoli has not independently reproduced this upstream detection"}}}
	text := strings.ToLower(o.Summary + " " + o.Details)
	ambiguous := false
	for _, word := range []string{"research", "proof of concept", "proof-of-concept", "empty package", "no malicious", "not malicious", "spam", "suspicious", "potentially malicious"} {
		if strings.Contains(text, word) {
			ambiguous = true
		}
	}
	clear := false
	for _, word := range []string{"malicious", "malware", "credential", "exfiltrat", "backdoor", "steal", "typosquat"} {
		if strings.Contains(text, word) {
			clear = true
		}
	}
	if ambiguous || !clear {
		r.Classification = "suspicious"
	}
	if len(r.Affected) == 0 {
		return r, false, errors.New("malware report contains no supported packages")
	}
	return r, s.Trusted && clear && !ambiguous, nil
}

type GHSA struct {
	ID          string     `json:"ghsa_id"`
	Type        string     `json:"type"`
	Summary     string     `json:"summary"`
	Description string     `json:"description"`
	URL         string     `json:"html_url"`
	Published   time.Time  `json:"published_at"`
	Updated     time.Time  `json:"updated_at"`
	Withdrawn   *time.Time `json:"withdrawn_at"`
	References  []string   `json:"references"`
	Identifiers []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Range string `json:"vulnerable_version_range"`
	} `json:"vulnerabilities"`
}

func ParseGitHub(b []byte, s config.Source) (model.Record, bool, error) {
	var o GHSA
	var r model.Record
	if err := json.Unmarshal(b, &o); err != nil {
		return r, false, err
	}
	if o.Type != "malware" {
		return r, false, nil
	}
	r = model.Record{SchemaVersion: model.Schema, ID: model.StableID(s.Name, o.ID), Aliases: []string{o.ID}, Classification: "malicious", Summary: o.Summary, PublishedAt: o.Published, WithdrawnAt: o.Withdrawn, References: o.References}
	if o.URL == "" {
		o.URL = "https://github.com/advisories/" + o.ID
	}
	for _, id := range o.Identifiers {
		r.Aliases = append(r.Aliases, id.Value)
	}
	for _, v := range o.Vulnerabilities {
		p := model.Identity{Ecosystem: v.Package.Ecosystem, Name: v.Package.Name}
		if err := p.Normalize(); err != nil {
			continue
		}
		a := model.Affected{Package: p, Scope: "unknown"}
		if v.Range != "" {
			a.Scope = "versions"
			constraint := v.Range
			if p.Ecosystem == "npm" {
				constraint = strings.ReplaceAll(constraint, ",", " ")
			}
			a.Ranges = []model.Range{{Type: "constraint", Constraint: constraint}}
		}
		r.Affected = append(r.Affected, a)
	}
	r.Sources = []model.Provenance{{Source: s.Name, ID: o.ID, URL: o.URL, License: s.License, Revision: model.Hash(b), RetrievedAt: time.Now().UTC()}}
	r.Evidence = []model.Evidence{{Explanation: "GitHub explicitly classifies this advisory as malware", Limitations: []string{"Zoli has not independently reproduced this upstream detection"}}}
	if len(r.Affected) == 0 {
		return r, false, nil
	}
	return r, s.Trusted, nil
}
