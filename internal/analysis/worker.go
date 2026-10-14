// SPDX-License-Identifier: Apache-2.0
package analysis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"zoli.dev/intel-feed/internal/config"
	"zoli.dev/intel-feed/internal/discovery"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/internal/netfetch"
	"zoli.dev/intel-feed/internal/store"
)

type Artifact struct {
	Package  model.Identity `json:"package"`
	URL      string         `json:"url"`
	SHA256   string         `json:"sha256,omitempty"`
	SHA512   string         `json:"sha512,omitempty"`
	Filename string         `json:"filename"`
}
type Result struct {
	Status      string           `json:"status"`
	Reason      string           `json:"reason,omitempty"`
	Artifact    Artifact         `json:"artifact"`
	Evidence    []model.Evidence `json:"evidence"`
	RulesHash   string           `json:"rules_sha256"`
	Limitations []string         `json:"limitations"`
}
type Worker struct {
	Store  *store.Store
	Client *netfetch.Client
	Config config.Analysis
	Rules  RuleSet
	Dir    string
}

func NewWorker(s *store.Store, c config.Config, rules RuleSet) *Worker {
	return &Worker{Store: s, Client: netfetch.New([]string{"registry.npmjs.org", "pypi.org", "files.pythonhosted.org"}, ""), Config: c.Analysis, Rules: rules, Dir: c.StorageDir}
}

type ArtifactJob struct {
	Release  discovery.Release `json:"release"`
	Artifact Artifact          `json:"artifact"`
}

func (w *Worker) RunOne(ctx context.Context) (bool, error) {
	j, err := w.Store.Claim(ctx, "static-artifact", 10*time.Minute)
	if err != nil {
		return false, err
	}
	if j != nil {
		return true, w.inspectArtifact(ctx, *j)
	}
	j, err = w.Store.Claim(ctx, "static", 5*time.Minute)
	if err != nil || j == nil {
		return false, err
	}
	var rel discovery.Release
	if err = json.Unmarshal(j.Payload, &rel); err != nil {
		return true, w.Store.Finish(ctx, *j, nil, err)
	}
	artifacts, err := w.Resolve(ctx, rel)
	if err != nil {
		return true, w.Store.Finish(ctx, *j, nil, err)
	}
	for _, a := range artifacts {
		key := "artifact:" + artifactIdentity(a) + ":" + w.Rules.Hash
		if err = w.Store.Enqueue(ctx, "static-artifact", key, ArtifactJob{rel, a}, j.Priority); err != nil {
			return true, w.Store.Finish(ctx, *j, nil, err)
		}
	}
	return true, w.Store.Finish(ctx, *j, map[string]any{"status": "resolved", "artifacts": len(artifacts)}, nil)
}
func (w *Worker) inspectArtifact(ctx context.Context, j store.Job) error {
	var job ArtifactJob
	if err := json.Unmarshal(j.Payload, &job); err != nil {
		return w.Store.Finish(ctx, j, nil, err)
	}
	rel, a := job.Release, job.Artifact
	allowed, err := w.Store.Reserve(ctx, "static_bytes", w.Config.MaxArtifactBytes, w.Config.DailyBytes)
	if err != nil {
		return err
	}
	if !allowed {
		return w.Store.Defer(ctx, j, "static download budget exhausted")
	}
	res, err := w.Client.Get(ctx, a.URL, w.Config.MaxArtifactBytes, "")
	if err != nil {
		if res.Status == 404 || res.Status == 410 {
			return w.Store.Finish(ctx, j, Result{Status: "skipped", Reason: "artifact unavailable", Artifact: a}, nil)
		}
		return w.Store.Finish(ctx, j, nil, err)
	}
	if a.SHA256 != "" && model.Hash(res.Body) != a.SHA256 {
		return w.Store.Finish(ctx, j, nil, errors.New("registry artifact hash mismatch"))
	}
	if err = verify512(res.Body, a.SHA512); err != nil {
		return w.Store.Finish(ctx, j, nil, err)
	}
	a.SHA256 = model.Hash(res.Body)
	a.Package.SHA256 = a.SHA256
	files, err := Inspect(res.Body, w.Config)
	if err != nil {
		return w.Store.Finish(ctx, j, Result{Status: "skipped", Reason: err.Error(), Artifact: a, Limitations: []string{"Uninspectable artifact is not a clean result"}}, nil)
	}
	evidence := Scan(files, a.Package.Ecosystem, a.SHA256, w.Rules)
	for _, signal := range rel.Signals {
		if strings.HasPrefix(signal, "name resembles") {
			evidence = append(evidence, model.Evidence{RuleID: "ZOLI-META-001", RuleVersion: "1.0.0", ArtifactSHA256: a.SHA256, Explanation: signal, Limitations: []string{"Naming similarity alone does not establish malware"}})
		}
	}
	if a.Package.Ecosystem == "npm" {
		for _, f := range files {
			if f.Name != "package/package.json" && f.Name != "package.json" {
				continue
			}
			var manifest struct {
				Scripts map[string]string `json:"scripts"`
			}
			if json.Unmarshal(f.Data, &manifest) != nil {
				continue
			}
			for _, key := range []string{"preinstall", "install", "postinstall"} {
				if manifest.Scripts[key] != "" {
					evidence = append(evidence, model.Evidence{RuleID: "ZOLI-META-002", RuleVersion: "1.0.0", ArtifactSHA256: a.SHA256, File: f.Name, Explanation: "Installation hook present: " + key, Limitations: []string{"A lifecycle script alone is not malware"}})
				}
			}
		}
	}
	result := Result{Status: "analyzed", Artifact: a, Evidence: evidence, RulesHash: w.Rules.Hash, Limitations: []string{"Static analysis does not prove safety", "Platform-specific artifacts may contain different behavior"}}
	if len(evidence) > 0 {
		if err = w.savePrivate(a, res.Body, result); err != nil {
			return w.Store.Finish(ctx, j, nil, err)
		}
		if err = w.candidate(ctx, a, evidence, w.Rules.Hash); err != nil {
			return w.Store.Finish(ctx, j, nil, err)
		}
		if w.Config.RuntimeEnabled {
			if err = w.Store.Enqueue(ctx, "runtime", "runtime:"+artifactIdentity(a), a, j.Priority+100); err != nil {
				return w.Store.Finish(ctx, j, nil, err)
			}
		}
	}
	return w.Store.Finish(ctx, j, result, nil)
}
func artifactIdentity(a Artifact) string {
	return model.Hash([]byte(a.Package.Ecosystem + ":" + a.Package.Registry + ":" + a.Package.Name + ":" + a.Package.Version + ":" + a.URL + ":" + a.SHA256 + ":" + a.SHA512))
}
func candidateID(a Artifact) string { return model.StableID("zoli", "artifact:"+artifactIdentity(a)) }
func (w *Worker) savePrivate(a Artifact, b []byte, result Result) error {
	dir := filepath.Join(w.Dir, "artifacts")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, a.SHA256), b, 0600); err != nil {
		return err
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, a.SHA256+".analysis.json"), data, 0600)
}
func (w *Worker) candidate(ctx context.Context, a Artifact, ev []model.Evidence, revision string) error {
	now := time.Now().UTC()
	id := "artifact:" + artifactIdentity(a)
	r := model.Record{SchemaVersion: model.Schema, ID: model.StableID("zoli", id), Classification: "suspicious", Summary: "Package artifact requires review", Affected: []model.Affected{{Package: a.Package, Versions: []string{a.Package.Version}, Scope: "versions"}}, Evidence: ev, Sources: []model.Provenance{{Source: "zoli", ID: id, URL: a.URL, License: "CC-BY-4.0", Revision: revision, RetrievedAt: now}}, OriginalLicense: "CC-BY-4.0"}
	return w.Store.Ingest(ctx, r, false)
}
func (w *Worker) Resolve(ctx context.Context, r discovery.Release) ([]Artifact, error) {
	q := r.Package
	if err := q.Normalize(); err != nil {
		return nil, err
	}
	switch q.Ecosystem {
	case "npm":
		res, err := w.Client.Get(ctx, "https://registry.npmjs.org/"+escapeName(q.Name)+"/"+escapeName(q.Version), 8<<20, "")
		if err != nil {
			return nil, err
		}
		var metadata struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Dist    struct {
				Tarball   string `json:"tarball"`
				Integrity string `json:"integrity"`
			} `json:"dist"`
		}
		if err = json.Unmarshal(res.Body, &metadata); err != nil {
			return nil, err
		}
		if metadata.Name != q.Name || metadata.Version != q.Version {
			return nil, errors.New("registry metadata identity mismatch")
		}
		if err = w.Client.CheckURL(metadata.Dist.Tarball); err != nil {
			return nil, err
		}
		integrity := ""
		for _, part := range strings.Fields(metadata.Dist.Integrity) {
			if strings.HasPrefix(part, "sha512-") {
				integrity = strings.TrimPrefix(part, "sha512-")
				break
			}
		}
		if integrity == "" {
			return nil, errors.New("npm artifact lacks sha512 integrity")
		}
		if _, err = base64.StdEncoding.DecodeString(integrity); err != nil {
			return nil, err
		}
		return []Artifact{{Package: q, URL: metadata.Dist.Tarball, SHA512: integrity, Filename: "package.tgz"}}, nil
	case "PyPI":
		res, err := w.Client.Get(ctx, "https://pypi.org/pypi/"+escapeName(q.Name)+"/"+escapeName(q.Version)+"/json", 8<<20, "")
		if err != nil {
			return nil, err
		}
		var meta struct {
			URLs []struct {
				URL      string            `json:"url"`
				Filename string            `json:"filename"`
				Digests  map[string]string `json:"digests"`
			} `json:"urls"`
		}
		if err = json.Unmarshal(res.Body, &meta); err != nil {
			return nil, err
		}
		out := []Artifact{}
		for _, f := range meta.URLs {
			if r.ArtifactID != "" && r.ArtifactID != f.Filename {
				continue
			}
			if err = w.Client.CheckURL(f.URL); err != nil {
				return nil, err
			}
			if len(f.Digests["sha256"]) != 64 {
				return nil, errors.New("PyPI artifact lacks sha256")
			}
			out = append(out, Artifact{Package: q, URL: f.URL, SHA256: f.Digests["sha256"], Filename: f.Filename})
		}
		if len(out) == 0 {
			return nil, errors.New("release has no available artifacts")
		}
		return out, nil
	}
	return nil, fmt.Errorf("analysis unsupported for %s", q.Ecosystem)
}
