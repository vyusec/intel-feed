// SPDX-License-Identifier: Apache-2.0
package feed

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"zoli.dev/intel-feed/internal/model"
)

func RecordsHash(records []model.Record) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	for _, r := range records {
		e.Encode(r)
	}
	return model.Hash(b.Bytes())
}
func ApplyDelta(records []model.Record, deltas []Delta) ([]model.Record, error) {
	byID := map[string]model.Record{}
	for _, r := range records {
		byID[r.ID] = r
	}
	for _, d := range deltas {
		switch d.Operation {
		case "upsert", "withdraw":
			if d.Record == nil || d.ID != d.Record.ID {
				return nil, errors.New("delta record identity mismatch")
			}
			if d.Operation == "withdraw" && d.Record.Status != "withdrawn" {
				return nil, errors.New("invalid withdrawal delta")
			}
			if err := d.Record.Validate(); err != nil {
				return nil, err
			}
			byID[d.ID] = *d.Record
		case "remove":
			if d.Record != nil {
				return nil, errors.New("remove delta cannot contain record")
			}
			delete(byID, d.ID)
		default:
			return nil, errors.New("unknown delta operation")
		}
	}
	out := []model.Record{}
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func DecodeRows(b []byte, onRow func([]byte) error) error {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: 512 << 20}
	scan := bufio.NewScanner(limited)
	scan.Buffer(make([]byte, 4096), 2<<20)
	for scan.Scan() {
		if err = onRow(scan.Bytes()); err != nil {
			return err
		}
	}
	if err = scan.Err(); err != nil {
		return err
	}
	if limited.N == 0 {
		return errors.New("feed expansion limit exceeded")
	}
	return nil
}
