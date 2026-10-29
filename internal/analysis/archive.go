// SPDX-License-Identifier: Apache-2.0
package analysis

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"math"
	"path"
	"strings"
	"unicode"
	"zoli.dev/intel-feed/internal/config"
)

func Inspect(b []byte, limits config.Analysis) ([]File, error) {
	if limits.MaxArtifactBytes <= 0 || limits.MaxExpandedBytes <= 0 || limits.MaxFiles <= 0 || int64(limits.MaxFiles) > (math.MaxInt64-limits.MaxExpandedBytes-1)/1024 {
		return nil, errors.New("invalid archive limits")
	}
	if int64(len(b)) > limits.MaxArtifactBytes {
		return nil, errors.New("artifact exceeds size limit")
	}
	files := []File{}
	seen := map[string]bool{}
	var expanded int64
	add := func(name string, size int64, reader io.Reader) error {
		if !safeName(name) || seen[name] {
			return errors.New("unsafe or duplicate archive path")
		}
		seen[name] = true
		if len(files) >= limits.MaxFiles || size < 0 || size > limits.MaxExpandedBytes-expanded {
			return errors.New("archive expansion limit")
		}
		data, err := io.ReadAll(io.LimitReader(reader, limits.MaxExpandedBytes-expanded+1))
		if err != nil {
			return err
		}
		expanded += int64(len(data))
		if expanded > limits.MaxExpandedBytes {
			return errors.New("archive expansion limit")
		}
		files = append(files, File{name, data})
		return nil
	}
	if bytes.HasPrefix(b, []byte("PK")) {
		zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			return nil, err
		}
		if len(zr.File) > limits.MaxFiles {
			return nil, errors.New("archive file count limit")
		}
		for _, f := range zr.File {
			if !safeName(strings.TrimSuffix(f.Name, "/")) {
				return nil, errors.New("unsafe archive path")
			}
			if f.FileInfo().IsDir() {
				name := strings.TrimSuffix(f.Name, "/")
				if seen[name] {
					return nil, errors.New("duplicate archive path")
				}
				seen[name] = true
				continue
			}
			if !f.Mode().IsRegular() {
				return nil, errors.New("archive links and special files are forbidden")
			}
			rd, err := f.Open()
			if err != nil {
				return nil, err
			}
			err = add(f.Name, int64(f.UncompressedSize64), rd)
			rd.Close()
			if err != nil {
				return nil, err
			}
		}
		if len(files) == 0 {
			return nil, errors.New("archive contains no inspectable files")
		}
		return files, nil
	}
	var r io.Reader = bytes.NewReader(b)
	if bytes.HasPrefix(b, []byte{0x1f, 0x8b}) {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	}
	// Limit archive framing and directory entries as well as regular file content.
	bounded := &io.LimitedReader{R: r, N: limits.MaxExpandedBytes + int64(limits.MaxFiles)*1024 + 1}
	tr := tar.NewReader(bounded)
	entries := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		entries++
		if entries > limits.MaxFiles {
			return nil, errors.New("archive entry count limit")
		}
		name := strings.TrimSuffix(h.Name, "/")
		if !safeName(name) {
			return nil, errors.New("unsafe archive path")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if seen[name] {
				return nil, errors.New("duplicate archive path")
			}
			seen[name] = true
			continue
		case tar.TypeReg, tar.TypeRegA:
			if err = add(name, h.Size, tr); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("archive links and special files are forbidden")
		}
	}
	// tar stops at its end markers before gzip necessarily checks its trailer.
	// Consume bounded padding to verify CRC/truncation and reject hidden archives.
	var padding [32 << 10]byte
	for {
		n, err := bounded.Read(padding[:])
		for _, b := range padding[:n] {
			if b != 0 {
				return nil, errors.New("non-padding data after tar archive")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if bounded.N == 0 {
		return nil, errors.New("archive framing limit")
	}
	if len(files) == 0 {
		return nil, errors.New("archive contains no inspectable files")
	}
	return files, nil
}
func safeName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.HasPrefix(s, "/") && !strings.Contains(s, "\\") && !strings.Contains(s, ":") && strings.IndexFunc(s, unicode.IsControl) < 0 && path.Clean(s) == s && !strings.HasPrefix(s, "../") && len(s) < 1024
}
