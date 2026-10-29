// SPDX-License-Identifier: Apache-2.0
package feed

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/internal/store"
)

type Artifact struct {
	Path         string    `json:"path"`
	SHA256       string    `json:"sha256"`
	Bytes        int64     `json:"bytes"`
	Kind         string    `json:"kind"`
	Ecosystem    string    `json:"ecosystem,omitempty"`
	FromSequence int64     `json:"from_sequence,omitempty"`
	ToSequence   int64     `json:"to_sequence,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}
type Manifest struct {
	SchemaVersion       string              `json:"schema_version"`
	Sequence            int64               `json:"sequence"`
	GeneratedAt         time.Time           `json:"generated_at"`
	RecordCount         int                 `json:"record_count"`
	RecordsSHA256       string              `json:"records_sha256"`
	RuleSetSHA256       string              `json:"rule_set_sha256"`
	Coverage            []model.Coverage    `json:"coverage"`
	Sources             []model.SourceState `json:"sources"`
	Files               []Artifact          `json:"files"`
	OriginalDataLicense string              `json:"original_data_license"`
	ImportedDataLicense string              `json:"imported_data_license"`
}

// Signature covers Manifest's exact bytes, not a reserialized representation.
type Envelope struct {
	Manifest  json.RawMessage `json:"manifest"`
	KeyID     string          `json:"key_id"`
	Signature string          `json:"signature"`
}
type Delta struct {
	Operation string        `json:"operation"`
	ID        string        `json:"id"`
	Record    *model.Record `json:"record,omitempty"`
}

func GenerateKey(path string) error {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		return err
	}
	return f.Sync()
}
func ReadKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	return ed25519.PrivateKey(key), nil
}
func Sign(m Manifest, key ed25519.PrivateKey) (Envelope, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return Envelope{}, err
	}
	pub := key.Public().(ed25519.PublicKey)
	return Envelope{b, model.Hash(pub)[:16], base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))}, nil
}
func Verify(e Envelope, key ed25519.PublicKey, minSequence int64) (Manifest, error) {
	var m Manifest
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || len(key) != ed25519.PublicKeySize || e.KeyID != model.Hash(key)[:16] || !ed25519.Verify(key, e.Manifest, sig) {
		return m, errors.New("invalid manifest signature")
	}
	if err = json.Unmarshal(e.Manifest, &m); err != nil {
		return m, err
	}
	if m.SchemaVersion != model.Schema || m.Sequence <= minSequence {
		return m, errors.New("unsupported schema or non-increasing sequence")
	}
	for _, f := range m.Files {
		if !safePath(f.Path) || len(f.SHA256) != 64 || f.Bytes < 0 {
			return m, errors.New("invalid artifact descriptor")
		}
	}
	return m, nil
}
func safePath(p string) bool {
	return p != "" && !filepath.IsAbs(p) && filepath.ToSlash(filepath.Clean(p)) == p && !strings.HasPrefix(p, "../") && !strings.Contains(p, "\\")
}
func VerifyArtifact(r io.Reader, a Artifact) ([]byte, error) {
	if a.Bytes < 0 || a.Bytes > 256<<20 {
		return nil, errors.New("invalid artifact size")
	}
	b, err := io.ReadAll(io.LimitReader(r, a.Bytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != a.Bytes || model.Hash(b) != a.SHA256 {
		return nil, errors.New("artifact checksum or size mismatch")
	}
	return b, nil
}
func Diff(old, current []model.Record) []Delta {
	previous := map[string]model.Record{}
	for _, r := range old {
		previous[r.ID] = r
	}
	out := []Delta{}
	for _, r := range current {
		p, exists := previous[r.ID]
		a, _ := json.Marshal(p)
		b, _ := json.Marshal(r)
		if !exists || !bytes.Equal(a, b) {
			op := "upsert"
			if r.Status == "withdrawn" {
				op = "withdraw"
			}
			copy := r
			out = append(out, Delta{op, r.ID, &copy})
		}
		delete(previous, r.ID)
	}
	for id := range previous {
		out = append(out, Delta{Operation: "remove", ID: id})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Deduplicate only reports linked by an explicit alias AND identical affected scope.
// Separate observations retain attribution; overlapping but different ranges are not merged.
func Deduplicate(records []model.Record) []model.Record {
	parent := make([]int, len(records))
	for i := range parent {
		parent[i] = i
	}
	var root func(int) int
	root = func(i int) int {
		if parent[i] != i {
			parent[i] = root(parent[i])
		}
		return parent[i]
	}
	index := map[string]int{}
	for i, r := range records {
		b, _ := json.Marshal(r.Affected)
		fingerprint := model.Hash(b) + r.Classification + r.Status
		for _, alias := range append(append([]string{}, r.Aliases...), r.ID) {
			key := alias + ":" + fingerprint
			if previous, ok := index[key]; ok {
				a, b := root(i), root(previous)
				if a > b {
					parent[a] = b
				} else {
					parent[b] = a
				}
			} else {
				index[key] = i
			}
		}
	}
	groups := map[int]int{}
	out := []model.Record{}
	for i, r := range records {
		group := root(i)
		if n, ok := groups[group]; ok {
			p := &out[n]
			p.Aliases = unique(append(append(p.Aliases, r.Aliases...), r.ID))
			p.Sources = append(p.Sources, r.Sources...)
			p.Evidence = append(p.Evidence, r.Evidence...)
			p.Reviews = append(p.Reviews, r.Reviews...)
			p.References = unique(append(p.References, r.References...))
			if r.ModifiedAt.After(p.ModifiedAt) {
				p.ModifiedAt = r.ModifiedAt
			}
		} else {
			groups[group] = len(out)
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func unique(xs []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

type Publisher struct {
	Store         *store.Store
	Dir           string
	Key           ed25519.PrivateKey
	RuleSetSHA256 string
	Coverage      []model.Coverage
}

func (p *Publisher) Publish(ctx context.Context) error {
	return p.Store.Lock(ctx, "publish", func() error {
		records, sources, err := p.Store.PublicationInputs(ctx)
		if err != nil {
			return err
		}
		records = Deduplicate(records)
		oldSeq, previousManifest, old, err := p.Store.Publication(ctx)
		if err != nil {
			return err
		}
		var previous Manifest
		var previousEnvelope Envelope
		if len(previousManifest) > 0 {
			if err = json.Unmarshal(previousManifest, &previousEnvelope); err != nil {
				return err
			}
			if err = json.Unmarshal(previousEnvelope.Manifest, &previous); err != nil {
				return err
			}
		}
		recordsHash := RecordsHash(records)
		sameRecords := recordsHash == previous.RecordsSHA256
		oldSources, _ := json.Marshal(previous.Sources)
		newSources, _ := json.Marshal(sources)
		coverage := p.Coverage
		if coverage == nil {
			coverage = model.DefaultCoverage()
		}
		previousCoverage, _ := json.Marshal(previous.Coverage)
		newCoverage, _ := json.Marshal(coverage)
		if oldSeq > 0 && sameRecords && bytes.Equal(oldSources, newSources) && bytes.Equal(previousCoverage, newCoverage) && previous.RuleSetSHA256 == p.RuleSetSHA256 && previousEnvelope.KeyID == model.Hash(p.Key.Public().(ed25519.PublicKey))[:16] {
			return nil
		}
		seq, err := p.Store.NextSequence(ctx)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		m := Manifest{SchemaVersion: model.Schema, Sequence: seq, GeneratedAt: now, RecordCount: len(records), RecordsSHA256: recordsHash, RuleSetSHA256: p.RuleSetSHA256, Coverage: coverage, Sources: sources, OriginalDataLicense: "CC-BY-4.0", ImportedDataLicense: "See each record.sources[].license"}
		for _, f := range previous.Files {
			if (f.Kind == "delta" && f.CreatedAt.After(now.Add(-30*24*time.Hour))) || (sameRecords && f.Kind == "snapshot") {
				m.Files = append(m.Files, f)
			}
		}
		if err = os.MkdirAll(p.Dir, 0755); err != nil {
			return err
		}
		stage, err := os.MkdirTemp(p.Dir, ".publication-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(stage)
		rel := fmt.Sprintf("snapshots/%020d", seq)
		write := func(name, kind, ecosystem string, items any) error {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			enc := json.NewEncoder(zw)
			enc.SetEscapeHTML(false)
			switch v := items.(type) {
			case []model.Record:
				for _, r := range v {
					if err := enc.Encode(r); err != nil {
						return err
					}
				}
			case []Delta:
				for _, r := range v {
					if err := enc.Encode(r); err != nil {
						return err
					}
				}
			default:
				return errors.New("invalid publication rows")
			}
			if err := zw.Close(); err != nil {
				return err
			}
			path := filepath.Join(stage, name)
			if err := writeSync(path, buf.Bytes(), 0644); err != nil {
				return err
			}
			a := Artifact{Path: rel + "/" + name, SHA256: model.Hash(buf.Bytes()), Bytes: int64(buf.Len()), Kind: kind, Ecosystem: ecosystem, CreatedAt: now}
			if kind == "delta" {
				a.FromSequence = oldSeq
				a.ToSequence = seq
			}
			m.Files = append(m.Files, a)
			return nil
		}
		if !sameRecords {
			if err = write("full.jsonl.gz", "snapshot", "", records); err != nil {
				return err
			}
			for _, ecosystem := range model.Ecosystems {
				subset := []model.Record{}
				for _, r := range records {
					for _, a := range r.Affected {
						if a.Package.Ecosystem == ecosystem {
							subset = append(subset, r)
							break
						}
					}
				}
				if err = write(strings.ToLower(ecosystem)+".jsonl.gz", "snapshot", ecosystem, subset); err != nil {
					return err
				}
			}
		}
		if err = write("delta.jsonl.gz", "delta", "", Diff(old, records)); err != nil {
			return err
		}
		env, err := Sign(m, p.Key)
		if err != nil {
			return err
		}
		b, err := json.Marshal(env)
		if err != nil {
			return err
		}
		if err = writeSync(filepath.Join(stage, "manifest.json"), b, 0644); err != nil {
			return err
		}
		if err = syncDir(stage); err != nil {
			return err
		}
		dest := filepath.Join(p.Dir, filepath.FromSlash(rel))
		if err = os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return err
		}
		if err = os.Rename(stage, dest); err != nil {
			return err
		}
		if err = syncDir(filepath.Dir(dest)); err != nil {
			return err
		}
		// The DB manifest is the single publication pointer used by both API and downloads.
		if err = p.Store.SavePublication(ctx, seq, b, records); err != nil {
			return err
		}
		if err = p.prune(m, previous); err != nil {
			return p.Store.Event(ctx, "publication_cleanup_failed", err.Error())
		}
		return nil
	})
}
func writeSync(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (p *Publisher) prune(m, previous Manifest) error {
	retain := map[string]bool{}
	files := map[string]bool{}
	for _, a := range append(append([]Artifact{}, m.Files...), previous.Files...) {
		retain[filepath.Dir(a.Path)] = true
		files[a.Path] = true
	}
	dirs, err := os.ReadDir(filepath.Join(p.Dir, "snapshots"))
	if err != nil {
		return err
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		rel := "snapshots/" + d.Name()
		full := filepath.Join(p.Dir, "snapshots", d.Name())
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !retain[rel] && info.ModTime().Before(m.GeneratedAt.Add(-30*24*time.Hour)) {
			if err = os.RemoveAll(full); err != nil {
				return err
			}
			continue
		}
		entries, err := os.ReadDir(full)
		if err != nil {
			return err
		}
		for _, f := range entries {
			path := rel + "/" + f.Name()
			if strings.HasSuffix(f.Name(), ".jsonl.gz") && !files[path] && info.ModTime().Before(m.GeneratedAt.Add(-24*time.Hour)) {
				if err = os.Remove(filepath.Join(full, f.Name())); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
