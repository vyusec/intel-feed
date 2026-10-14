// SPDX-License-Identifier: Apache-2.0
package analysis

import (
	"context"
	"deps.dev/util/semver"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"zoli.dev/intel-feed/internal/discovery"
	"zoli.dev/intel-feed/internal/model"
)

// Prefetch obtains dependency archives without installing or importing any package.
// Unsupported source/marker/platform requirements are reported, never guessed away.
func (w *Worker) Prefetch(ctx context.Context, root Artifact, rootBytes []byte, dir string) ([]string, error) {
	limits := []string{}
	if root.Package.Ecosystem == "npm" {
		limits = append(limits, "Offline sandbox uses a flat dependency layout; conflicting versions may prevent installation")
	}
	queue := []struct {
		a Artifact
		b []byte
	}{{root, rootBytes}}
	seen := map[string]bool{root.Package.Name + "@" + root.Package.Version: true}
	var downloaded int64
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		files, err := Inspect(item.b, w.Config)
		if err != nil {
			return limits, err
		}
		requirements := map[string]string{}
		for _, f := range files {
			if root.Package.Ecosystem == "npm" && (f.Name == "package/package.json" || f.Name == "package.json") {
				var m struct {
					Dependencies map[string]string `json:"dependencies"`
					Optional     map[string]string `json:"optionalDependencies"`
					Peers        map[string]string `json:"peerDependencies"`
				}
				if json.Unmarshal(f.Data, &m) == nil {
					for k, v := range m.Dependencies {
						requirements[k] = v
					}
					for k, v := range m.Optional {
						requirements[k] = v
					}
					if len(m.Peers) > 0 {
						limits = append(limits, "Peer dependency resolution is not reproduced")
					}
				}
			}
			if root.Package.Ecosystem == "PyPI" && strings.HasSuffix(f.Name, ".dist-info/METADATA") {
				for _, line := range strings.Split(string(f.Data), "\n") {
					if !strings.HasPrefix(line, "Requires-Dist:") {
						continue
					}
					spec := strings.TrimSpace(strings.TrimPrefix(line, "Requires-Dist:"))
					if strings.ContainsAny(spec, ";@[ ") {
						limits = append(limits, "Conditional, extras or direct dependency not prefetched: "+strings.Split(spec, ";")[0])
						continue
					}
					name := spec
					constraint := "*"
					if n := strings.IndexAny(spec, "(<>=!~"); n >= 0 {
						name = strings.TrimSpace(spec[:n])
						constraint = strings.Trim(strings.TrimSpace(spec[n:]), "()")
					}
					requirements[name] = constraint
				}
			}
		}
		names := []string{}
		for n := range requirements {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			if len(seen) >= 100 {
				limits = append(limits, "Dependency prefetch capped at 100 package versions")
				return limits, nil
			}
			p := item.a.Package
			p.Name = name
			p.Version = ""
			p.SHA256 = ""
			if err = p.Normalize(); err != nil {
				limits = append(limits, "Unsupported dependency identity")
				continue
			}
			constraint := requirements[name]
			version, err := w.selectVersion(ctx, p, constraint)
			if err != nil {
				limits = append(limits, fmt.Sprintf("Dependency %s unresolved: %s", p.Name, err))
				continue
			}
			p.Version = version
			key := p.Name + "@" + version
			if seen[key] {
				continue
			}
			seen[key] = true
			arts, err := w.Resolve(ctx, discovery.Release{Package: p})
			if err != nil {
				limits = append(limits, "Dependency archive unavailable: "+key)
				continue
			}
			selected := []Artifact{}
			if p.Ecosystem == "npm" {
				selected = arts[:1]
			} else {
				for _, a := range arts {
					if strings.HasSuffix(a.Filename, "-none-any.whl") {
						selected = append(selected, a)
						break
					}
				}
			}
			if len(selected) == 0 {
				limits = append(limits, "No universal wheel prefetched for "+key)
				continue
			}
			for _, a := range selected {
				res, err := w.Client.Get(ctx, a.URL, w.Config.MaxArtifactBytes, "")
				if err != nil {
					limits = append(limits, "Dependency download failed: "+key)
					continue
				}
				downloaded += int64(len(res.Body))
				if downloaded > w.Config.MaxExpandedBytes {
					return append(limits, "Dependency download budget reached"), nil
				}
				if a.SHA256 != "" && a.SHA256 != model.Hash(res.Body) {
					return limits, fmt.Errorf("dependency hash mismatch: %s", key)
				}
				if err = verify512(res.Body, a.SHA512); err != nil {
					return limits, err
				}
				name := a.Filename
				if p.Ecosystem == "npm" {
					name = model.Hash(res.Body) + ".tgz"
				}
				if !safeName(name) || strings.Contains(name, "/") {
					return limits, fmt.Errorf("invalid dependency filename")
				}
				if err = os.WriteFile(filepath.Join(dir, name), res.Body, 0600); err != nil {
					return limits, err
				}
				queue = append(queue, struct {
					a Artifact
					b []byte
				}{a, res.Body})
			}
		}
	}
	return limits, nil
}
func (w *Worker) selectVersion(ctx context.Context, p model.Identity, constraint string) (string, error) {
	var s semver.System
	endpoint := ""
	if p.Ecosystem == "npm" {
		s = semver.NPM
		endpoint = "https://registry.npmjs.org/" + escapeName(p.Name)
	} else {
		s = semver.PyPI
		endpoint = "https://pypi.org/pypi/" + escapeName(p.Name) + "/json"
	}
	if constraint == "latest" {
		constraint = "*"
	}
	if strings.HasPrefix(constraint, "npm:") {
		return "", fmt.Errorf("npm aliases are not resolved")
	}
	c, err := s.ParseConstraint(constraint)
	if err != nil {
		return "", err
	}
	res, err := w.Client.Get(ctx, endpoint, 16<<20, "")
	if err != nil {
		return "", err
	}
	var meta struct {
		Versions map[string]json.RawMessage `json:"versions"`
		Releases map[string]json.RawMessage `json:"releases"`
	}
	if err = json.Unmarshal(res.Body, &meta); err != nil {
		return "", err
	}
	versions := meta.Versions
	if p.Ecosystem == "PyPI" {
		versions = meta.Releases
	}
	best := ""
	var bv *semver.Version
	for raw := range versions {
		v, err := s.Parse(raw)
		if err != nil || v.IsPrerelease() || !c.MatchVersion(v) {
			continue
		}
		if bv == nil || v.Compare(bv) > 0 {
			best = raw
			bv = v
		}
	}
	if best == "" {
		return "", fmt.Errorf("no matching stable release")
	}
	return best, nil
}
