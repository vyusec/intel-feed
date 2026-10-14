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
	"testing"
	"zoli.dev/intel-feed/internal/feed"
	"zoli.dev/intel-feed/internal/model"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestSignedDeltaUpdateAndRollback(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	r := Record{SchemaVersion: "1.0", ID: "ZOLI-fixture", Classification: "malicious", Status: "published", Summary: "Synthetic", Affected: []model.Affected{{Package: Identity{Ecosystem: "npm", Name: "example", Registry: "https://registry.npmjs.org"}, Versions: []string{"1.0.0"}, Scope: "versions"}}, Evidence: []model.Evidence{{Explanation: "Synthetic"}}, Sources: []model.Provenance{{Source: "fixture", ID: "1", Revision: "1", License: "CC-BY-4.0"}}}
	oldRecords := []Record{r}
	oldEnvelope, _ := feed.Sign(Manifest{SchemaVersion: "1.0", Sequence: 1, RecordCount: 1, RecordsSHA256: feed.RecordsHash(oldRecords)}, key)
	old := Snapshot{oldEnvelope, oldRecords}
	r.Status = "withdrawn"
	newRecords := []Record{r}
	deltas := feed.Diff(oldRecords, newRecords)
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	enc := json.NewEncoder(gz)
	for _, d := range deltas {
		enc.Encode(d)
	}
	gz.Close()
	data := b.Bytes()
	a := feed.Artifact{Path: "snapshots/2/delta.jsonl.gz", SHA256: model.Hash(data), Bytes: int64(len(data)), Kind: "delta", FromSequence: 1, ToSequence: 2}
	newEnvelope, _ := feed.Sign(Manifest{SchemaVersion: "1.0", Sequence: 2, RecordCount: 1, RecordsSHA256: feed.RecordsHash(newRecords), Files: []feed.Artifact{a}}, key)
	manifest, _ := json.Marshal(newEnvelope)
	c, err := New("https://feed.example/feed", pub)
	if err != nil {
		t.Fatal(err)
	}
	c.http.HTTP = &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
		body := manifest
		if req.URL.Path != "/feed/latest.json" {
			body = data
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
	updated, err := c.Update(context.Background(), &old)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Records[0].Status != "withdrawn" {
		t.Fatal(updated)
	}
	manifest, _ = json.Marshal(oldEnvelope)
	if _, err = c.Update(context.Background(), &updated); err == nil {
		t.Fatal("accepted rollback")
	}
}
