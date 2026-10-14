package feed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"zoli.dev/intel-feed/internal/model"
)

func TestManifestAuthenticationAndRollback(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	e, err := Sign(Manifest{SchemaVersion: model.Schema, Sequence: 10}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(e, pub, 9); err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(e, pub, 10); err == nil {
		t.Fatal("accepted replay")
	}
	forged := e
	var m Manifest
	json.Unmarshal(e.Manifest, &m)
	m.Sequence = 11
	forged.Manifest, _ = json.Marshal(m)
	if _, err = Verify(forged, pub, 9); err == nil {
		t.Fatal("accepted tampering")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err = Verify(e, other, 0); err == nil {
		t.Fatal("accepted wrong key")
	}
}
func TestArtifactIntegrity(t *testing.T) {
	b := []byte("download")
	a := Artifact{Bytes: int64(len(b)), SHA256: model.Hash(b)}
	if _, err := VerifyArtifact(bytes.NewReader(b), a); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyArtifact(bytes.NewReader([]byte("tampered")), a); err == nil {
		t.Fatal("accepted tampered artifact")
	}
}
func TestWithdrawalDeltaAndScopeDeduplication(t *testing.T) {
	old := model.Record{ID: "a", Status: "published"}
	next := old
	next.Status = "withdrawn"
	d := Diff([]model.Record{old}, []model.Record{next})
	if len(d) != 1 || d[0].Operation != "withdraw" {
		t.Fatal(d)
	}
	a := model.Record{ID: "a", Aliases: []string{"MAL-1"}, Classification: "malicious", Status: "published", Affected: []model.Affected{{Scope: "versions", Versions: []string{"1.0.0"}}}, Sources: []model.Provenance{{Source: "first"}}}
	b := a
	b.ID = "b"
	b.Sources = []model.Provenance{{Source: "second"}}
	out := Deduplicate([]model.Record{a, b})
	if len(out) != 1 || len(out[0].Sources) != 2 {
		t.Fatal(out)
	}
	b.Affected = []model.Affected{{Scope: "versions", Versions: []string{"2.0.0"}}}
	if len(Deduplicate([]model.Record{a, b})) != 2 {
		t.Fatal("merged distinct scopes")
	}
}
func TestDeltaRejectsMismatchedIdentity(t *testing.T) {
	if _, err := ApplyDelta(nil, []Delta{{Operation: "upsert", ID: "a", Record: &model.Record{ID: "b"}}}); err == nil {
		t.Fatal("accepted mismatched ID")
	}
}
func TestTransitiveAliasDeduplication(t *testing.T) {
	a := model.Record{ID: "a", Aliases: []string{"one"}, Status: "published"}
	b := a
	b.ID = "b"
	b.Aliases = []string{"two"}
	c := a
	c.ID = "c"
	c.Aliases = []string{"one", "two"}
	if out := Deduplicate([]model.Record{a, b, c}); len(out) != 1 {
		t.Fatal(out)
	}
}
