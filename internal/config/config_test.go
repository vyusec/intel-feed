package config

import (
	"testing"
	"time"
)

func TestRepositoryConfigurationLoads(t *testing.T) {
	c, err := Load("../../config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Analysis.DailyRuntimeJobs != 100 || !c.Analysis.Enabled {
		t.Fatal(c)
	}
	if c.IngestInterval != 15*time.Minute || c.DiscoveryInterval != time.Minute || c.PublishInterval != time.Minute {
		t.Fatal("unexpected continuous update cadence", c)
	}
}
func TestRunnerConfigHasNoProductionDependencies(t *testing.T) {
	c, err := Load("../../deploy/runner.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Analysis.SandboxRuntime != "runsc" {
		t.Fatal(c)
	}
}

func TestContinuousDeploymentEnablesBoundedStaticAnalysis(t *testing.T) {
	c, err := Load("../../deploy/continuous.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Analysis.Enabled || c.Analysis.RuntimeEnabled || c.IngestInterval != 15*time.Minute || c.DiscoveryInterval != time.Minute || c.PublishInterval != time.Minute {
		t.Fatal(c)
	}
	if c.SigningKey != "secrets/feed.key" || c.DatabaseEnv != "DATABASE_URL" || c.FeedDir != "data/feed" || c.StorageDir != "data/private" {
		t.Fatal("continuous deployment must reuse the existing trust and storage", c)
	}
}
