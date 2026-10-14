// SPDX-License-Identifier: Apache-2.0
package config

import (
	"errors"
	"gopkg.in/yaml.v3"
	"os"
	"time"
)

type Config struct {
	Listen            string        `yaml:"listen"`
	DatabaseEnv       string        `yaml:"database_env"`
	OperatorTokenEnv  string        `yaml:"operator_token_env"`
	RunnerTokenEnv    string        `yaml:"runner_token_env"`
	GitHubTokenEnv    string        `yaml:"github_token_env"`
	StorageDir        string        `yaml:"storage_dir"`
	FeedDir           string        `yaml:"feed_dir"`
	SigningKey        string        `yaml:"signing_key"`
	RulesFile         string        `yaml:"rules_file"`
	IngestInterval    time.Duration `yaml:"ingest_interval"`
	DiscoveryInterval time.Duration `yaml:"discovery_interval"`
	PublishInterval   time.Duration `yaml:"publish_interval"`
	Sources           []Source      `yaml:"sources"`
	Analysis          Analysis      `yaml:"analysis"`
	API               API           `yaml:"api"`
}
type Source struct {
	Name       string   `yaml:"name"`
	Type       string   `yaml:"type"`
	URL        string   `yaml:"url"`
	License    string   `yaml:"license"`
	Trusted    bool     `yaml:"trusted"`
	Ecosystems []string `yaml:"ecosystems"`
}
type Analysis struct {
	Enabled            bool                `yaml:"enabled"`
	RuntimeEnabled     bool                `yaml:"runtime_enabled"`
	DailyBytes         int64               `yaml:"daily_bytes"`
	DailyRuntimeJobs   int                 `yaml:"daily_runtime_jobs"`
	RuntimeConcurrency int                 `yaml:"runtime_concurrency"`
	MaxArtifactBytes   int64               `yaml:"max_artifact_bytes"`
	MaxExpandedBytes   int64               `yaml:"max_expanded_bytes"`
	MaxFiles           int                 `yaml:"max_files"`
	ProtectedPackages  map[string][]string `yaml:"protected_packages"`
	Watchlist          map[string][]string `yaml:"watchlist"`
	SandboxRuntime     string              `yaml:"sandbox_runtime"`
	SandboxTraceDir    string              `yaml:"sandbox_trace_dir"`
	SandboxImages      map[string]string   `yaml:"sandbox_images"`
	RuntimeTimeout     time.Duration       `yaml:"runtime_timeout"`
}
type API struct {
	RequestsPerMinute int    `yaml:"requests_per_minute"`
	KeysEnv           string `yaml:"keys_env"`
}

func Default() Config {
	return Config{
		Listen: "127.0.0.1:8080", DatabaseEnv: "DATABASE_URL", OperatorTokenEnv: "ZOLI_OPERATOR_TOKEN", RunnerTokenEnv: "ZOLI_RUNNER_TOKEN", GitHubTokenEnv: "GITHUB_TOKEN",
		StorageDir: "data/private", FeedDir: "data/feed", SigningKey: "secrets/feed.key", RulesFile: "rules/rules.yaml", IngestInterval: 30 * time.Minute, DiscoveryInterval: 10 * time.Minute, PublishInterval: 5 * time.Minute,
		Analysis: Analysis{DailyBytes: 1 << 30, DailyRuntimeJobs: 100, RuntimeConcurrency: 1, MaxArtifactBytes: 20 << 20, MaxExpandedBytes: 100 << 20, MaxFiles: 10000, SandboxRuntime: "runsc", SandboxTraceDir: "/var/log/zoli-runsc", RuntimeTimeout: 5 * time.Minute},
		API:      API{RequestsPerMinute: 60, KeysEnv: "ZOLI_API_KEYS"},
	}
}
func Load(path string) (Config, error) {
	c := Default()
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	d.KnownFields(true)
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if c.IngestInterval < time.Minute || c.DiscoveryInterval < time.Minute || c.PublishInterval < time.Second {
		return c, errors.New("invalid scheduler interval")
	}
	if c.Analysis.MaxArtifactBytes <= 0 || c.Analysis.MaxExpandedBytes <= 0 || c.Analysis.MaxFiles <= 0 || c.Analysis.DailyBytes <= 0 || c.Analysis.DailyRuntimeJobs < 0 {
		return c, errors.New("invalid analysis budgets")
	}
	if c.Analysis.RuntimeTimeout <= 0 || c.Analysis.RuntimeTimeout > 10*time.Minute || c.API.RequestsPerMinute <= 0 || c.Analysis.RuntimeConcurrency < 1 {
		return c, errors.New("invalid runtime timeout or rate limit")
	}
	if c.Analysis.RuntimeEnabled && !c.Analysis.Enabled {
		return c, errors.New("runtime analysis requires analysis enabled")
	}
	seen := map[string]bool{}
	for _, s := range c.Sources {
		if s.Name == "" || s.URL == "" || s.License == "" || seen[s.Name] {
			return c, errors.New("sources require unique names, URLs and licenses")
		}
		seen[s.Name] = true
		if s.Type != "osv" && s.Type != "github" {
			return c, errors.New("unsupported source type")
		}
	}
	return c, nil
}
