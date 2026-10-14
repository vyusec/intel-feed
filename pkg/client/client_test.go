package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"zoli.dev/intel-feed/internal/feed"
)

func TestCacheAuthenticatesRecordContents(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	records := []Record{{ID: "record", Summary: "original"}}
	e, err := feed.Sign(Manifest{SchemaVersion: "1.0", Sequence: 1, RecordCount: 1, RecordsSHA256: feed.RecordsHash(records)}, key)
	if err != nil {
		t.Fatal(err)
	}
	s := Snapshot{e, records}
	if _, err = s.Verify(pub); err != nil {
		t.Fatal(err)
	}
	s.Records[0].Summary = "tampered"
	if _, err = s.Verify(pub); err == nil {
		t.Fatal("accepted cache tampering")
	}
}
