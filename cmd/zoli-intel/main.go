// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"zoli.dev/intel-feed/internal/analysis"
	"zoli.dev/intel-feed/internal/config"
	"zoli.dev/intel-feed/internal/feed"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/internal/service"
	"zoli.dev/intel-feed/internal/store"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func output(v any) error { e := json.NewEncoder(os.Stdout); e.SetIndent("", "  "); return e.Encode(v) }
func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: zoli-intel serve|worker|runner|ingest|publish|migrate|keygen|publickey|review|list|inspect|history|import|analyze|sandbox|evaluate|verify")
	}
	command := args[0]
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	configPath := f.String("config", "config.yaml", "configuration file")
	url := f.String("url", "http://127.0.0.1:8080", "service URL")
	id := f.String("id", "", "report ID")
	file := f.String("file", "", "record or manifest file")
	key := f.String("key", "secrets/feed.key", "signing key path")
	action := f.String("action", "", "approve, reject or withdraw")
	revision := f.Int("revision", 0, "expected report revision")
	reviewer := f.String("reviewer", "", "reviewer identity")
	rationale := f.String("rationale", "", "review rationale")
	classification := f.String("classification", "", "malicious or suspicious")
	status := f.String("status", "pending", "report status filter")
	after := f.String("after", "", "pagination cursor")
	artifact := f.String("artifact", "", "archive to inspect")
	ecosystem := f.String("ecosystem", "npm", "artifact ecosystem")
	rulesPath := f.String("rules", "rules/rules.yaml", "rules to reproduce")
	descriptor := f.String("descriptor", "", "artifact descriptor JSON")
	corpus := f.String("corpus", "testdata/evaluation/corpus.json", "held-out evaluation corpus")
	publicKey := f.String("public-key", "", "pinned base64 verification key")
	minSequence := f.Int64("min-sequence", 0, "last accepted sequence")
	once := f.Bool("once", false, "process at most one job")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments; use named flags")
	}
	switch command {
	case "keygen":
		return feed.GenerateKey(*key)
	case "publickey":
		k, err := feed.ReadKey(*key)
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)))
		return nil
	case "analyze":
		c := config.Default()
		if *artifact == "" {
			return errors.New("--artifact required")
		}
		b, err := readLimited(*artifact, c.Analysis.MaxArtifactBytes)
		if err != nil {
			return err
		}
		rules, err := analysis.LoadRules(*rulesPath)
		if err != nil {
			return err
		}
		files, err := analysis.Inspect(b, c.Analysis)
		if err != nil {
			return err
		}
		return output(analysis.Result{Status: "analyzed", Artifact: analysis.Artifact{Package: model.Identity{Ecosystem: *ecosystem}, SHA256: model.Hash(b)}, RulesHash: rules.Hash, Evidence: analysis.Scan(files, *ecosystem, model.Hash(b), rules), Limitations: []string{"Static results require review; no safe verdict is issued"}})
	case "evaluate":
		rules, err := analysis.LoadRules(*rulesPath)
		if err != nil {
			return err
		}
		return evaluate(*corpus, rules)
	case "verify":
		b, err := readLimited(*file, 2<<20)
		if err != nil {
			return err
		}
		var e feed.Envelope
		if err = json.Unmarshal(b, &e); err != nil {
			return err
		}
		pub, err := base64.StdEncoding.DecodeString(*publicKey)
		if err != nil {
			return err
		}
		m, err := feed.Verify(e, pub, *minSequence)
		if err != nil {
			return err
		}
		return output(m)
	case "list", "inspect", "history", "review", "import":
		token := os.Getenv("ZOLI_OPERATOR_TOKEN")
		path := ""
		method := "GET"
		var body any
		switch command {
		case "list":
			path = "/admin/reports?status=" + *status + "&after=" + *after
		case "inspect":
			path = "/admin/reports/" + *id
		case "history":
			path = "/admin/reports/" + *id + "/history"
		case "review":
			path = "/admin/review"
			method = "POST"
			body = map[string]any{"id": *id, "action": *action, "revision": *revision, "reviewer": *reviewer, "rationale": *rationale, "classification": *classification}
		case "import":
			path = "/admin/import"
			method = "POST"
			b, err := readLimited(*file, 2<<20)
			if err != nil {
				return err
			}
			var record model.Record
			if err = json.Unmarshal(b, &record); err != nil {
				return err
			}
			body = record
		}
		return operatorRequest(ctx, *url, path, method, token, body)
	}
	c, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if command == "runner" || command == "sandbox" {
		r := analysis.Runner{URL: *url, Token: os.Getenv(c.RunnerTokenEnv), Config: c.Analysis, Dir: c.StorageDir}
		if command == "sandbox" {
			b, err := readLimited(*descriptor, 2<<20)
			if err != nil {
				return err
			}
			var a analysis.Artifact
			if err = json.Unmarshal(b, &a); err != nil {
				return err
			}
			return output(r.Analyze(ctx, a))
		}
		for {
			did, err := r.RunOne(ctx)
			if err != nil {
				return err
			}
			if *once {
				return nil
			}
			if !did {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(10 * time.Second):
				}
			}
		}
	}
	if command == "migrate" {
		s, err := store.Open(ctx, os.Getenv(c.DatabaseEnv))
		if err != nil {
			return err
		}
		defer s.DB.Close()
		return s.Migrate(ctx)
	}
	if command == "worker" {
		s, err := store.Open(ctx, os.Getenv(c.DatabaseEnv))
		if err != nil {
			return err
		}
		defer s.DB.Close()
		if err = s.Migrate(ctx); err != nil && !errors.Is(err, store.ErrLocked) {
			return err
		}
		rules, err := analysis.LoadRules(c.RulesFile)
		if err != nil {
			return err
		}
		w := analysis.NewWorker(s, c, rules)
		for {
			did, err := w.RuntimeEvidenceOne(ctx)
			if err != nil {
				return err
			}
			if !did && c.Analysis.Enabled {
				did, err = w.RunOne(ctx)
				if err != nil {
					return err
				}
			}
			if *once {
				return nil
			}
			if !did {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(5 * time.Second):
				}
			}
		}
	}
	s, err := service.New(ctx, c)
	if err != nil {
		return err
	}
	defer s.Store.DB.Close()
	switch command {
	case "serve":
		return s.Run(ctx)
	case "ingest":
		return s.Ingest.Run(ctx)
	case "publish":
		return s.Publisher.Publish(ctx)
	case "worker":
		for {
			did, err := s.Worker.RuntimeEvidenceOne(ctx)
			if err != nil {
				return err
			}
			if !did && c.Analysis.Enabled {
				did, err = s.Worker.RunOne(ctx)
				if err != nil {
					return err
				}
			}
			if *once {
				return nil
			}
			if !did {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(5 * time.Second):
				}
			}
		}
	default:
		return fmt.Errorf("unknown command %s", command)
	}
}
func readLimited(path string, max int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("file path required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, errors.New("file exceeds size limit")
	}
	return b, err
}
func operatorRequest(ctx context.Context, base, path, method, token string, body any) error {
	if len(token) < 32 {
		return errors.New("ZOLI_OPERATOR_TOKEN must be set")
	}
	u, err := url.Parse(base)
	if err != nil || u.User != nil || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost"))) {
		return errors.New("operator requests require HTTPS or local loopback")
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, data)
	}
	_, err = os.Stdout.Write(append(data, '\n'))
	return err
}
func evaluate(path string, rules analysis.RuleSet) error {
	b, err := readLimited(path, 2<<20)
	if err != nil {
		return err
	}
	var corpus struct {
		Version   string `json:"version"`
		Synthetic bool   `json:"synthetic"`
		Cases     []struct {
			ID        string `json:"id"`
			Ecosystem string `json:"ecosystem"`
			Label     string `json:"label"`
			Files     []struct {
				Name string `json:"name"`
				Path string `json:"path"`
			} `json:"files"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(b, &corpus); err != nil {
		return err
	}
	tp, fp, tn, fn := 0, 0, 0, 0
	cases := []map[string]any{}
	for _, c := range corpus.Cases {
		files := []analysis.File{}
		for _, f := range c.Files {
			data, err := readLimited(filepath.Join(filepath.Dir(path), f.Path), 1<<20)
			if err != nil {
				return err
			}
			files = append(files, analysis.File{Name: f.Name, Data: data})
		}
		ev := analysis.Scan(files, c.Ecosystem, "evaluation", rules)
		positive := len(ev) > 0
		switch {
		case positive && c.Label == "malicious":
			tp++
		case positive && c.Label == "benign":
			fp++
		case !positive && c.Label == "benign":
			tn++
		case !positive && c.Label == "malicious":
			fn++
		default:
			return errors.New("invalid evaluation label")
		}
		cases = append(cases, map[string]any{"id": c.ID, "label": c.Label, "signals": len(ev)})
	}
	return output(map[string]any{"corpus_version": corpus.Version, "synthetic": corpus.Synthetic, "rules_sha256": rules.Hash, "true_positives": tp, "false_positives": fp, "true_negatives": tn, "false_negatives": fn, "cases": cases, "limitations": []string{"Synthetic regression corpus; not an estimate of real-world malware detection quality", "Rules produce review signals, not automatic malware verdicts"}})
}
