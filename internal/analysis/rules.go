// SPDX-License-Identifier: Apache-2.0
package analysis

import (
	"bytes"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"regexp"
	"sort"
	"strings"
	"zoli.dev/intel-feed/internal/model"
)

type Rule struct {
	ID          string   `yaml:"id" json:"id"`
	Version     string   `yaml:"version" json:"version"`
	Explanation string   `yaml:"explanation" json:"explanation"`
	Ecosystems  []string `yaml:"ecosystems" json:"ecosystems"`
	All         []string `yaml:"all" json:"all"`
	FilePattern string   `yaml:"file_pattern" json:"file_pattern"`
}
type RuleSet struct {
	Version string `yaml:"version" json:"version"`
	Rules   []Rule `yaml:"rules" json:"rules"`
	Hash    string `yaml:"-" json:"sha256"`
}
type File struct {
	Name string
	Data []byte
}

func LoadRules(path string) (RuleSet, error) {
	var r RuleSet
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err = d.Decode(&r); err != nil {
		return r, err
	}
	if r.Version == "" || len(r.Rules) == 0 {
		return r, errors.New("rules require a version and entries")
	}
	seen := map[string]bool{}
	for _, rule := range r.Rules {
		if rule.ID == "" || seen[rule.ID] || rule.Version == "" || rule.Explanation == "" || len(rule.All) == 0 {
			return r, errors.New("invalid rule")
		}
		seen[rule.ID] = true
		for _, pattern := range append(append([]string{}, rule.All...), rule.FilePattern) {
			if _, err = regexp.Compile(pattern); err != nil {
				return r, fmt.Errorf("%s: %w", rule.ID, err)
			}
		}
	}
	r.Hash = model.Hash(b)
	return r, nil
}
func Scan(files []File, ecosystem, digest string, rules RuleSet) []model.Evidence {
	out := []model.Evidence{}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	for _, file := range files {
		if bytes.IndexByte(file.Data, 0) >= 0 {
			continue
		}
		for _, rule := range rules.Rules {
			if !contains(rule.Ecosystems, ecosystem) {
				continue
			}
			if !regexp.MustCompile(rule.FilePattern).MatchString(file.Name) {
				continue
			}
			line := 0
			ok := true
			for _, pattern := range rule.All {
				loc := regexp.MustCompile(pattern).FindIndex(file.Data)
				if loc == nil {
					ok = false
					break
				}
				if line == 0 {
					line = bytes.Count(file.Data[:loc[0]], []byte("\n")) + 1
				}
			}
			if ok {
				out = append(out, model.Evidence{RuleID: rule.ID, RuleVersion: rule.Version, ArtifactSHA256: digest, File: file.Name, Line: line, Explanation: rule.Explanation, Reproduce: "zoli-intel analyze --artifact <sha256-matching-archive> --ecosystem " + ecosystem + " --rules <recorded-rules.yaml>", Limitations: []string{"Pattern conjunction is an investigation signal; human review is required", "Static patterns in one file do not establish executed data flow"}})
			}
		}
	}
	return out
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
