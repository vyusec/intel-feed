package config

import "testing"

func TestRepositoryConfigurationLoads(t *testing.T) {
	c, err := Load("../../config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Analysis.DailyRuntimeJobs != 100 || !c.Analysis.Enabled {
		t.Fatal(c)
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
