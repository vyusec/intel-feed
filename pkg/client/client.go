// SPDX-License-Identifier: Apache-2.0
// Package client verifies, caches and queries Zoli's public feed locally.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"zoli.dev/intel-feed/internal/api"
	"zoli.dev/intel-feed/internal/feed"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/internal/netfetch"
)

type Identity = model.Identity
type Record = model.Record
type Manifest = feed.Manifest
type Envelope = feed.Envelope
type QueryResponse = api.QueryResponse
type Snapshot struct {
	Envelope Envelope `json:"envelope"`
	Records  []Record `json:"records"`
}
type Client struct {
	BaseURL   string
	PublicKey ed25519.PublicKey
	http      *netfetch.Client
}

func New(base string, key ed25519.PublicKey) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("HTTPS feed base URL and pinned Ed25519 key required")
	}
	return &Client{strings.TrimRight(base, "/"), key, netfetch.New([]string{u.Hostname()}, "")}, nil
}
func (s Snapshot) Verify(key ed25519.PublicKey) (Manifest, error) {
	m, err := feed.Verify(s.Envelope, key, -1)
	if err != nil {
		return m, err
	}
	if len(s.Records) != m.RecordCount || feed.RecordsHash(s.Records) != m.RecordsSHA256 {
		return m, errors.New("cached records do not match signed manifest")
	}
	return m, nil
}
func (s Snapshot) Query(q Identity, key ed25519.PublicKey) (QueryResponse, error) {
	m, err := s.Verify(key)
	if err != nil {
		return QueryResponse{}, err
	}
	return api.Query(q, m, s.Records)
}

// QueryBatch authenticates the cache once and indexes records for a dependency set.
func (s Snapshot) QueryBatch(packages []Identity, key ed25519.PublicKey) ([]QueryResponse, error) {
	m, err := s.Verify(key)
	if err != nil {
		return nil, err
	}
	index := api.BuildIndex(s.Records)
	out := []QueryResponse{}
	for _, q := range packages {
		if err = q.Normalize(); err != nil {
			return nil, err
		}
		result, err := api.Query(q, m, index[q.Ecosystem+":"+q.Name])
		if err != nil {
			return nil, err
		}
		out = append(out, result)
	}
	return out, nil
}
func (c *Client) Update(ctx context.Context, previous *Snapshot) (Snapshot, error) {
	var out Snapshot
	last := int64(0)
	if previous != nil {
		m, err := previous.Verify(c.PublicKey)
		if err != nil {
			return out, err
		}
		last = m.Sequence
	}
	res, err := c.http.Get(ctx, c.BaseURL+"/latest.json", 2<<20, "")
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(res.Body, &out.Envelope); err != nil {
		return out, err
	}
	// An unchanged signed manifest is a no-op; an older one is rejected.
	m, err := feed.Verify(out.Envelope, c.PublicKey, last-1)
	if err != nil {
		return out, err
	}
	if m.Sequence < last {
		return out, errors.New("feed rollback rejected")
	}
	if m.Sequence == last && previous != nil {
		if !bytes.Equal(out.Envelope.Manifest, previous.Envelope.Manifest) {
			return out, errors.New("same-sequence manifest equivocation rejected")
		}
		return *previous, nil
	}
	fetch := func(a feed.Artifact) ([]byte, error) {
		r, err := c.http.Get(ctx, c.BaseURL+"/"+a.Path, 256<<20, "")
		if err != nil {
			return nil, err
		}
		return feed.VerifyArtifact(bytes.NewReader(r.Body), a)
	}
	if previous != nil {
		records := append([]Record{}, previous.Records...)
		seq := last
		for seq < m.Sequence {
			var next *feed.Artifact
			for i := range m.Files {
				a := &m.Files[i]
				if a.Kind == "delta" && a.FromSequence == seq && a.ToSequence > seq {
					next = a
					break
				}
			}
			if next == nil {
				break
			}
			b, err := fetch(*next)
			if err != nil {
				return out, err
			}
			deltas := []feed.Delta{}
			if err = feed.DecodeRows(b, func(row []byte) error {
				var d feed.Delta
				if err := json.Unmarshal(row, &d); err != nil {
					return err
				}
				deltas = append(deltas, d)
				return nil
			}); err != nil {
				return out, err
			}
			records, err = feed.ApplyDelta(records, deltas)
			if err != nil {
				return out, err
			}
			seq = next.ToSequence
		}
		if seq == m.Sequence {
			out.Records = records
			if _, err = out.Verify(c.PublicKey); err != nil {
				return out, err
			}
			return out, nil
		}
	}
	for _, a := range m.Files {
		if a.Kind != "snapshot" || a.Ecosystem != "" {
			continue
		}
		b, err := fetch(a)
		if err != nil {
			return out, err
		}
		out.Records = []Record{}
		if err = feed.DecodeRows(b, func(row []byte) error {
			var r Record
			if err := json.Unmarshal(row, &r); err != nil {
				return err
			}
			if err := r.Validate(); err != nil {
				return err
			}
			out.Records = append(out.Records, r)
			return nil
		}); err != nil {
			return out, err
		}
		_, err = out.Verify(c.PublicKey)
		return out, err
	}
	return out, errors.New("manifest lacks full snapshot")
}
func (s Snapshot) Save(path string) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".feed-cache-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func Load(path string, key ed25519.PublicKey) (Snapshot, error) {
	var s Snapshot
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if len(b) > 512<<20 {
		return s, errors.New("cache exceeds size limit")
	}
	if err = json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	_, err = s.Verify(key)
	return s, err
}
