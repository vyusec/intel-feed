// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"zoli.dev/intel-feed/internal/config"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/internal/netfetch"
	"zoli.dev/intel-feed/internal/store"
)

type Pipeline struct {
	Store   *store.Store
	Client  *netfetch.Client
	Dir     string
	Sources []config.Source
}

func (p *Pipeline) Run(ctx context.Context) error {
	var errs []error
	for _, s := range p.Sources {
		if err := p.RunSource(ctx, s, false); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name, err))
		}
	}
	return errors.Join(errs...)
}
func (p *Pipeline) RunSource(ctx context.Context, s config.Source, reconcile bool) error {
	return p.Store.Lock(ctx, "source:"+s.Name, func() error {
		st, err := p.Store.Source(ctx, s.Name)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		st.LastAttempt = &now
		st.Coverage = "published_malware_reports"
		original := st.Cursor
		var cursor string
		switch s.Type {
		case "github":
			cursor, err = p.github(ctx, s, st.Cursor, reconcile)
		case "osv":
			cursor, err = p.osv(ctx, s, st.Cursor, reconcile)
		default:
			err = errors.New("unsupported source")
		}
		if err != nil {
			st.Cursor = original
			st.Error = err.Error()
		} else {
			st.Cursor = cursor
			st.LastSuccess = &now
			st.Error = ""
		}
		saveErr := p.Store.SaveSource(ctx, st)
		return errors.Join(err, saveErr)
	})
}
func (p *Pipeline) save(ctx context.Context, s config.Source, b []byte) error {
	var r model.Record
	var auto bool
	var err error
	if s.Type == "github" {
		r, auto, err = ParseGitHub(b, s)
	} else {
		r, auto, err = ParseOSV(b, s)
	}
	if err != nil {
		return err
	}
	if r.ID == "" {
		return nil
	}
	if err = p.raw(b); err != nil {
		return err
	}
	return p.Store.Ingest(ctx, r, auto)
}
func (p *Pipeline) raw(b []byte) error {
	path := filepath.Join(p.Dir, "raw", model.Hash(b)+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}
func (p *Pipeline) github(ctx context.Context, s config.Source, cursor string, reconcile bool) (string, error) {
	high := cursor
	for _, withdrawn := range []bool{false, true} {
		next, err := p.githubPass(ctx, s, cursor, reconcile, withdrawn)
		if err != nil {
			return cursor, err
		}
		if next != "" {
			t, err := time.Parse(time.RFC3339Nano, next)
			if err != nil {
				return cursor, err
			}
			old, _ := time.Parse(time.RFC3339Nano, high)
			if high == "" || t.After(old) {
				high = next
			}
		}
	}
	return high, nil
}
func (p *Pipeline) githubPass(ctx context.Context, s config.Source, cursor string, reconcile bool, withdrawn bool) (string, error) {
	u, err := url.Parse(s.URL)
	if err != nil {
		return cursor, err
	}
	q := u.Query()
	q.Set("type", "malware")
	q.Set("is_withdrawn", fmt.Sprint(withdrawn))
	q.Set("per_page", "100")
	q.Set("sort", "updated")
	q.Set("direction", "asc")
	if cursor != "" && !reconcile {
		t, err := time.Parse(time.RFC3339Nano, cursor)
		if err != nil {
			return cursor, err
		}
		q.Set("modified", ">="+t.Add(-time.Hour).Format(time.RFC3339))
	}
	u.RawQuery = q.Encode()
	next := u.String()
	high := cursor
	for pages := 0; next != ""; pages++ {
		if pages > 20000 {
			return cursor, errors.New("pagination limit exceeded")
		}
		res, err := p.Client.Get(ctx, next, 16<<20, "")
		if err != nil {
			return cursor, err
		}
		var reports []json.RawMessage
		if err = json.Unmarshal(res.Body, &reports); err != nil {
			return cursor, err
		}
		for _, b := range reports {
			var a GHSA
			if err = json.Unmarshal(b, &a); err != nil {
				return cursor, err
			}
			if err = p.save(ctx, s, b); err != nil {
				return cursor, err
			}
			ts := a.Updated.UTC().Format(time.RFC3339Nano)
			if a.Updated.IsZero() {
				return cursor, errors.New("advisory lacks updated timestamp")
			}
			previous, _ := time.Parse(time.RFC3339Nano, high)
			if high == "" || a.Updated.After(previous) {
				high = ts
			}
		}
		next = ""
		for _, link := range strings.Split(res.Header.Get("Link"), ",") {
			if strings.Contains(link, `rel="next"`) {
				parts := strings.Split(link, ";")
				next = strings.Trim(strings.TrimSpace(parts[0]), "<>")
				v, err := url.Parse(next)
				if err != nil || v.Host != u.Host || v.Path != u.Path || v.Query().Get("type") != "malware" {
					return cursor, errors.New("invalid pagination destination")
				}
			}
		}
	}
	return high, nil
}
func (p *Pipeline) osv(ctx context.Context, s config.Source, cursor string, reconcile bool) (string, error) {
	var since time.Time
	var err error
	if cursor != "" {
		since, err = time.Parse(time.RFC3339Nano, cursor)
		if err != nil {
			return cursor, err
		}
		since = since.Add(-time.Hour)
	}
	start := time.Now().UTC()
	seen := map[string]bool{}
	for _, ecosystem := range s.Ecosystems {
		base := strings.TrimRight(s.URL, "/") + "/" + url.PathEscape(ecosystem)
		if cursor == "" || reconcile {
			if err = p.bulk(ctx, s, base+"/all.zip", seen); err != nil {
				return cursor, err
			}
			continue
		}
		res, err := p.Client.Get(ctx, base+"/modified_id.csv", 64<<20, "")
		if err != nil {
			return cursor, err
		}
		rows := csv.NewReader(bytes.NewReader(res.Body))
		rows.FieldsPerRecord = -1
		ids := []string{}
		for {
			row, err := rows.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return cursor, err
			}
			if len(row) != 2 {
				return cursor, errors.New("invalid OSV modified index")
			}
			var id, ts string
			// OSV has exposed timestamp,id and id,timestamp layouts; recognize both.
			if strings.HasPrefix(row[0], "MAL-") {
				id, ts = row[0], row[1]
			} else if strings.HasPrefix(row[1], "MAL-") {
				id, ts = row[1], row[0]
			} else {
				continue
			}
			t, err := time.Parse(time.RFC3339Nano, ts)
			if err != nil {
				return cursor, err
			}
			if reconcile || !t.Before(since) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			res, err := p.Client.Get(ctx, "https://api.osv.dev/v1/vulns/"+url.PathEscape(id), 2<<20, "")
			if err != nil {
				return cursor, err
			}
			if err = p.save(ctx, s, res.Body); err != nil {
				return cursor, err
			}
		}
	}
	if cursor == "" || reconcile {
		if err = p.reconcileMissing(ctx, s, seen); err != nil {
			return cursor, err
		}
	}
	return start.Format(time.RFC3339Nano), nil
}
func (p *Pipeline) bulk(ctx context.Context, s config.Source, rawURL string, seen map[string]bool) error {
	res, err := p.Client.Get(ctx, rawURL, 512<<20, "")
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(res.Body), int64(len(res.Body)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if !strings.HasPrefix(filepath.Base(f.Name), "MAL-") || !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		if f.UncompressedSize64 > 2<<20 {
			return errors.New("OSV record exceeds size limit")
		}
		rd, err := f.Open()
		if err != nil {
			return err
		}
		b, err := io.ReadAll(io.LimitReader(rd, (2<<20)+1))
		rd.Close()
		if err != nil {
			return err
		}
		if len(b) > 2<<20 {
			return errors.New("OSV record exceeds size limit")
		}
		if err = p.save(ctx, s, b); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		var report OSV
		if err = json.Unmarshal(b, &report); err != nil {
			return err
		}
		seen[report.ID] = true
	}
	return nil
}

// Absence is handled only after a complete, successful reconciliation of every configured ecosystem.
func (p *Pipeline) reconcileMissing(ctx context.Context, s config.Source, seen map[string]bool) error {
	records, err := p.Store.Records(ctx, false)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, r := range records {
		if len(r.Sources) == 0 || r.Sources[0].Source != s.Name || r.WithdrawnAt != nil || seen[r.Sources[0].ID] {
			continue
		}
		r.WithdrawnAt = &now
		r.Evidence = append(r.Evidence, model.Evidence{Explanation: "Report absent from a complete source reconciliation; upstream assertion retracted"})
		if err = p.Store.Ingest(ctx, r, false); err != nil {
			return err
		}
	}
	return nil
}
