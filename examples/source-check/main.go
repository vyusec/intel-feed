// SPDX-License-Identifier: Apache-2.0
// source-check validates downloaded upstream reports without a database or
// package execution. It does not establish ingestion or deployment readiness.
package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"zoli.dev/intel-feed/internal/config"
	"zoli.dev/intel-feed/internal/ingest"
)

type result struct {
	Input       string   `json:"input"`
	Accepted    int      `json:"accepted"`
	Unsupported int      `json:"unsupported"`
	Withdrawals int      `json:"withdrawn_without_identity"`
	Failed      int      `json:"failed"`
	Errors      []string `json:"errors,omitempty"`
}

func (out *result) check(b []byte, github bool) {
	source := config.Source{Name: "source-check", License: "Apache-2.0", Trusted: true}
	parse := ingest.ParseOSV
	if github {
		parse = ingest.ParseGitHub
		source.License = "CC-BY-4.0"
	}
	r, _, err := parse(b, source)
	if errors.Is(err, ingest.ErrUnsupportedReport) {
		out.Unsupported++
		return
	}
	if err == nil && r.ID == "" {
		return
	}
	if err == nil && r.WithdrawnAt != nil && len(r.Affected) == 0 {
		out.Withdrawals++
		return
	}
	if err == nil {
		err = r.Validate()
	}
	if err != nil {
		out.Failed++
		if len(out.Errors) < 10 {
			out.Errors = append(out.Errors, fmt.Sprintf("%s: %v", r.ID, err))
		}
	} else {
		out.Accepted++
	}
}

func validate(path string) (result, error) {
	out := result{Input: path}
	if strings.HasSuffix(path, ".zip") {
		zr, err := zip.OpenReader(path)
		if err != nil {
			return out, err
		}
		defer zr.Close()
		stat, err := os.Stat(path)
		if err != nil {
			return out, err
		}
		if stat.Size() > 512<<20 {
			return out, errors.New("archive exceeds source download limit")
		}
		for _, f := range zr.File {
			if !strings.HasPrefix(filepath.Base(f.Name), "MAL-") || !strings.HasSuffix(f.Name, ".json") {
				continue
			}
			if f.UncompressedSize64 > 2<<20 {
				return out, fmt.Errorf("oversize upstream report: %s", f.Name)
			}
			rd, err := f.Open()
			if err != nil {
				return out, err
			}
			b, err := io.ReadAll(io.LimitReader(rd, (2<<20)+1))
			rd.Close()
			if err != nil {
				return out, err
			}
			if len(b) > 2<<20 {
				return out, fmt.Errorf("oversize upstream report: %s", f.Name)
			}
			out.check(b, false)
		}
	} else {
		f, err := os.Open(path)
		if err != nil {
			return out, err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, (16<<20)+1))
		if err != nil {
			return out, err
		}
		if len(b) > 16<<20 {
			return out, errors.New("JSON input exceeds source response limit")
		}
		trimmed := strings.TrimSpace(string(b))
		if strings.HasPrefix(trimmed, "[") {
			var rows []json.RawMessage
			if err = json.Unmarshal(b, &rows); err != nil {
				return out, err
			}
			for _, r := range rows {
				out.check(r, true)
			}
		} else {
			out.check(b, false)
		}
	}
	return out, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: source-check OSV-all.zip|OSV-report.json|GitHub-advisories.json ...")
		os.Exit(2)
	}
	failed := false
	for _, path := range os.Args[1:] {
		out, err := validate(path)
		if err != nil {
			out.Failed++
			out.Errors = append(out.Errors, err.Error())
		}
		if err = json.NewEncoder(os.Stdout).Encode(out); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		failed = failed || out.Failed > 0
	}
	if failed {
		os.Exit(1)
	}
}
