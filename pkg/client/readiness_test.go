package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
	"zoli.dev/intel-feed/internal/feed"
	"zoli.dev/intel-feed/internal/model"
)

func readinessRecord(t *testing.T) Record {
	t.Helper()
	r := Record{
		SchemaVersion: "1.0", ID: "ZOLI-readiness", Classification: "suspicious",
		Status: "published", Summary: "Controlled readiness fixture", Revision: 1,
		Affected: []model.Affected{{Package: Identity{Ecosystem: "npm", Name: "readiness-fixture"}, Scope: "versions", Versions: []string{"1.0.0"}}},
		Evidence: []model.Evidence{{Explanation: "Inert test fixture"}},
		Sources:  []model.Provenance{{Source: "fixture", ID: "readiness", Revision: "v1", License: "CC-BY-4.0"}},
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return r
}

func readinessArtifact(t *testing.T, path, kind string, rows any) (feed.Artifact, []byte) {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if err := json.NewEncoder(gz).Encode(rows); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	data := b.Bytes()
	return feed.Artifact{Path: path, Kind: kind, Bytes: int64(len(data)), SHA256: model.Hash(data)}, data
}

func readinessEnvelope(t *testing.T, key ed25519.PrivateKey, sequence int64, records []Record, files ...feed.Artifact) (Envelope, []byte) {
	t.Helper()
	now := time.Now().UTC()
	e, err := feed.Sign(Manifest{SchemaVersion: "1.0", Sequence: sequence, GeneratedAt: now, Sources: []model.SourceState{{Name: "fixture", LastSuccess: &now}}, RecordCount: len(records), RecordsSHA256: feed.RecordsHash(records), Coverage: model.DefaultCoverage(), Files: files}, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return e, b
}

func readinessClient(t *testing.T, pub ed25519.PublicKey, serve func(*http.Request) []byte) *Client {
	t.Helper()
	c, err := New("https://feed.example/feed", pub)
	if err != nil {
		t.Fatal(err)
	}
	c.http.HTTP = &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(serve(req)))}, nil
	})}
	return c
}

func TestSnapshotDownloadFallbackAndCacheReload(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := readinessRecord(t)
	records := []Record{r}
	a, data := readinessArtifact(t, "snapshots/4/all.jsonl.gz", "snapshot", r)
	_, manifest := readinessEnvelope(t, key, 4, records, a)
	old, _ := readinessEnvelope(t, key, 1, records)
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial_snapshot", true: "missing_delta_chain"}[cached], func(t *testing.T) {
			paths := []string{}
			c := readinessClient(t, pub, func(req *http.Request) []byte {
				paths = append(paths, req.URL.Path)
				switch req.URL.Path {
				case "/feed/latest.json":
					return manifest
				case "/feed/" + a.Path:
					return data
				default:
					t.Fatalf("unexpected request: %s", req.URL.Path)
					return nil
				}
			})
			var previous *Snapshot
			if cached {
				previous = &Snapshot{old, records}
			}
			s, err := c.Update(context.Background(), previous)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(paths, []string{"/feed/latest.json", "/feed/" + a.Path}) {
				t.Fatal("full snapshot was not fetched", paths)
			}
			path := filepath.Join(t.TempDir(), "cache.json")
			if err = s.Save(path); err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(path, pub)
			if err != nil {
				t.Fatal(err)
			}
			m, err := loaded.Verify(pub)
			if err != nil || m.Sequence != 4 || m.RecordCount != 1 {
				t.Fatal(m, err)
			}
			out, err := loaded.Query(Identity{Ecosystem: "npm", Name: "readiness-fixture", Version: "1.0.0"}, pub)
			if err != nil || out.Status != "known_match" || len(out.Matches) != 1 || out.Matches[0].Certainty != "exact" {
				t.Fatal(out, err)
			}
			loaded.Records[0].Summary = "tampered on disk"
			if err = loaded.Save(path); err != nil {
				t.Fatal(err)
			}
			if _, err = Load(path, pub); err == nil {
				t.Fatal("accepted tampered cache file")
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("cache permissions", info, err)
			}
		})
	}
}

func TestClientRejectsTamperedDownloads(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := readinessRecord(t)
	a, data := readinessArtifact(t, "snapshots/2/all.jsonl.gz", "snapshot", r)
	env, manifest := readinessEnvelope(t, key, 2, []Record{r}, a)
	forged := env
	forged.Manifest = bytes.Replace(env.Manifest, []byte(`"sequence":2`), []byte(`"sequence":3`), 1)
	forgedJSON, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	tamperedData := append([]byte{}, data...)
	tamperedData[len(tamperedData)-1] ^= 1
	changed := r
	changed.Summary = "different record set"
	_, wrongHash := readinessEnvelope(t, key, 2, []Record{changed}, a)
	for _, tc := range []struct {
		name     string
		manifest []byte
		data     []byte
	}{
		{"manifest_signature", forgedJSON, data},
		{"compressed_artifact", manifest, tamperedData},
		{"resulting_record_hash", wrongHash, data},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := readinessClient(t, pub, func(req *http.Request) []byte {
				if req.URL.Path == "/feed/latest.json" {
					return tc.manifest
				}
				return tc.data
			})
			if _, err := c.Update(context.Background(), nil); err == nil {
				t.Fatal("accepted tampered download")
			}
		})
	}
}

func TestUnchangedManifestDoesNotDownloadArtifacts(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	records := []Record{readinessRecord(t)}
	env, manifest := readinessEnvelope(t, key, 1, records)
	c := readinessClient(t, pub, func(req *http.Request) []byte {
		if req.URL.Path != "/feed/latest.json" {
			t.Fatalf("unchanged manifest fetched an artifact: %s", req.URL.Path)
		}
		return manifest
	})
	previous := Snapshot{env, records}
	updated, err := c.Update(context.Background(), &previous)
	if err != nil || !reflect.DeepEqual(updated, previous) {
		t.Fatal("unchanged publication did not preserve the cache", err)
	}
}

func TestSameSequenceEquivocationIsRejected(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := readinessRecord(t)
	env, _ := readinessEnvelope(t, key, 4, []Record{r})
	previous := Snapshot{Envelope: env, Records: []Record{r}}
	m, err := previous.Verify(pub)
	if err != nil {
		t.Fatal(err)
	}
	m.RuleSetSHA256 = "different signed publication at same sequence"
	changed, err := feed.Sign(m, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	c := readinessClient(t, pub, func(r *http.Request) []byte {
		if r.URL.Path != "/feed/latest.json" {
			t.Fatal("equivocation attempted artifact download")
		}
		return b
	})
	before, _ := json.Marshal(previous)
	if _, err = c.Update(context.Background(), &previous); err == nil {
		t.Fatal("accepted same-sequence equivocation")
	}
	after, _ := json.Marshal(previous)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected update mutated cache")
	}
}

func TestCorrectionAndWithdrawalUpdateCachedLookups(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := readinessRecord(t)
	env, _ := readinessEnvelope(t, key, 1, []Record{r})
	previous := Snapshot{env, []Record{r}}
	for _, step := range []struct {
		sequence int64
		version  string
		status   string
		want     string
	}{
		{2, "2.0.0", "published", "known_match"},
		{3, "2.0.0", "withdrawn", "no_known_match"},
	} {
		t.Run(step.status, func(t *testing.T) {
			changed := readinessRecord(t)
			changed.Affected[0].Versions = []string{step.version}
			changed.Status = step.status
			changed.Revision = int(step.sequence)
			op := "upsert"
			if step.status == "withdrawn" {
				op = "withdraw"
			}
			a, data := readinessArtifact(t, "delta.jsonl.gz", "delta", feed.Delta{Operation: op, ID: changed.ID, Record: &changed})
			a.FromSequence, a.ToSequence = step.sequence-1, step.sequence
			_, manifest := readinessEnvelope(t, key, step.sequence, []Record{changed}, a)
			c := readinessClient(t, pub, func(req *http.Request) []byte {
				switch req.URL.Path {
				case "/feed/latest.json":
					return manifest
				case "/feed/" + a.Path:
					return data
				default:
					t.Fatalf("expected delta update, got %s", req.URL.Path)
					return nil
				}
			})
			updated, err := c.Update(context.Background(), &previous)
			if err != nil {
				t.Fatal(err)
			}
			for version, want := range map[string]string{"1.0.0": "no_known_match", step.version: step.want} {
				out, err := updated.Query(Identity{Ecosystem: "npm", Name: "readiness-fixture", Version: version}, pub)
				if err != nil || out.Status != want || out.Sequence != step.sequence {
					t.Fatal(version, out, err)
				}
			}
			if previous.Records[0].Status != "published" {
				t.Fatal("delta update changed the previously verified cache")
			}
			previous = updated
		})
	}
}
