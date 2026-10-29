// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
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
)

type reportStore interface {
	Lock(context.Context, string, func() error) error
	Source(context.Context, string) (model.SourceState, error)
	SaveSource(context.Context, model.SourceState) error
	Ingest(context.Context, model.Record, bool) error
	Get(context.Context, string) (model.Record, error)
	Records(context.Context, bool) ([]model.Record, error)
	Event(context.Context, string, string) error
}

type Pipeline struct {
	Store   reportStore
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
		if err = p.Store.SaveSource(ctx, st); err != nil {
			return err
		}
		original := st.Cursor
		gaps := append([]string(nil), st.Gaps...)
		var cursor string
		switch s.Type {
		case "github":
			cursor, err = p.github(ctx, s, st.Cursor, reconcile, &gaps)
		case "osv":
			cursor, err = p.osv(ctx, s, st.Cursor, reconcile, &gaps)
		default:
			err = errors.New("unsupported source")
		}
		if err != nil {
			st.Cursor = original
			st.Error = err.Error()
		} else {
			st.Cursor = cursor
			completed := time.Now().UTC()
			st.LastSuccess = &completed
			st.Error = ""
		}
		st.Gaps = gaps
		saveErr := p.Store.SaveSource(ctx, st)
		return errors.Join(err, saveErr)
	})
}
func (p *Pipeline) save(ctx context.Context, s config.Source, b []byte, gaps *[]string) error {
	var r model.Record
	var auto bool
	var err error
	if s.Type == "github" {
		r, auto, err = ParseGitHub(b, s)
	} else {
		r, auto, err = ParseOSV(b, s)
	}
	if err != nil {
		var unsupported *unsupportedReport
		if errors.As(err, &unsupported) {
			if err = p.raw(b); err != nil {
				return err
			}
			if err = p.Store.Event(ctx, "ingest_skip", s.Name+": "+unsupported.Error()); err != nil {
				return err
			}
			*gaps = appendSourceGap(*gaps, unsupported.Error())
			return nil
		}
		return err
	}
	if r.ID == "" {
		return nil
	}
	if err = p.raw(b); err != nil {
		return err
	}
	// Withdrawn upstream records may omit package data. Retain the old identity
	// only to retract its prior assertion; never invent a new affected scope.
	if r.WithdrawnAt != nil && len(r.Affected) == 0 {
		old, err := p.Store.Get(ctx, r.ID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		r.Affected = old.Affected
	}
	return p.Store.Ingest(ctx, r, auto)
}

func appendSourceGap(gaps []string, detail string) []string {
	for _, gap := range gaps {
		if gap == detail {
			return gaps
		}
	}
	if len(gaps) >= 20 {
		gaps = gaps[len(gaps)-19:]
	}
	return append(gaps, detail)
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
func (p *Pipeline) github(ctx context.Context, s config.Source, cursor string, reconcile bool, gaps *[]string) (string, error) {
	high := cursor
	for _, withdrawn := range []bool{false, true} {
		next, err := p.githubPass(ctx, s, cursor, reconcile, withdrawn, gaps)
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
func (p *Pipeline) githubPass(ctx context.Context, s config.Source, cursor string, reconcile bool, withdrawn bool, gaps *[]string) (string, error) {
	u, err := url.Parse(s.URL)
	if err != nil {
		return cursor, err
	}
	q := u.Query()
	q.Set("type", "malware")
	q.Set("is_withdrawn", fmt.Sprint(withdrawn))
	q.Set("per_page", "100")
	q.Set("sort", "updated")
	q.Set("direction", "desc")
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
			if a.Updated.IsZero() {
				return cursor, errors.New("advisory lacks updated timestamp")
			}
			if err = p.save(ctx, s, b, gaps); err != nil {
				return cursor, fmt.Errorf("%s: %w", a.ID, err)
			}
			ts := a.Updated.UTC().Format(time.RFC3339Nano)
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
func (p *Pipeline) osv(ctx context.Context, s config.Source, cursor string, reconcile bool, gaps *[]string) (string, error) {
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
	// OSV moves package-less withdrawals into [EMPTY]. Poll that export as well
	// so they retract old identities during incremental updates, not a day later.
	ecosystems := append([]string(nil), s.Ecosystems...)
	if len(ecosystems) > 0 {
		ecosystems = append(ecosystems, "[EMPTY]")
	}
	for _, ecosystem := range ecosystems {
		base := strings.TrimRight(s.URL, "/") + "/" + url.PathEscape(ecosystem)
		if cursor == "" || reconcile {
			if err = p.bulk(ctx, s, base+"/all.zip", seen, gaps); err != nil {
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
				if !seen[id] {
					ids = append(ids, id)
					seen[id] = true
				}
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			res, err := p.Client.Get(ctx, "https://api.osv.dev/v1/vulns/"+url.PathEscape(id), 2<<20, "")
			if err != nil {
				return cursor, err
			}
			if err = p.save(ctx, s, res.Body, gaps); err != nil {
				return cursor, fmt.Errorf("%s: %w", id, err)
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
func (p *Pipeline) bulk(ctx context.Context, s config.Source, rawURL string, seen map[string]bool, gaps *[]string) error {
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
		if err = p.save(ctx, s, b, gaps); err != nil {
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
