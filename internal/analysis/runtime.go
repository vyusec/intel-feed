// SPDX-License-Identifier: Apache-2.0
package analysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"zoli.dev/intel-feed/internal/config"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/internal/netfetch"
	"zoli.dev/intel-feed/internal/store"
)

type RuntimeResult struct {
	JobID       int64            `json:"job_id"`
	LeaseToken  string           `json:"lease_token"`
	Artifact    Artifact         `json:"artifact"`
	Evidence    []model.Evidence `json:"evidence"`
	Status      string           `json:"status"`
	Limitations []string         `json:"limitations"`
	TraceSHA256 string           `json:"trace_sha256,omitempty"`
}
type Runner struct {
	URL    string
	Token  string
	Config config.Analysis
	Dir    string
}

func (r *Runner) RunOne(ctx context.Context) (bool, error) {
	if !strings.HasPrefix(r.URL, "https://") {
		return false, errors.New("runner broker must use HTTPS")
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(path string, input, output any) error {
		b, err := json.Marshal(input)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(r.URL, "/")+path, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+r.Token)
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("runner broker HTTP %d", res.StatusCode)
		}
		if output != nil {
			return json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(output)
		}
		return nil
	}
	var claim struct {
		Job *store.Job `json:"job"`
	}
	if err := request("/internal/runner/claim", struct{}{}, &claim); err != nil {
		return false, err
	}
	if claim.Job == nil {
		return false, nil
	}
	j := claim.Job
	var a Artifact
	if err := json.Unmarshal(j.Payload, &a); err != nil {
		return true, err
	}
	analysisCtx, cancel := context.WithTimeout(ctx, r.Config.RuntimeTimeout+4*time.Minute)
	defer cancel()
	result := r.Analyze(analysisCtx, a)
	result.JobID = j.ID
	result.LeaseToken = j.LeaseToken
	if err := request("/internal/runner/result", result, nil); err != nil {
		return true, err
	}
	return true, nil
}
func (r *Runner) Analyze(ctx context.Context, a Artifact) RuntimeResult {
	out := RuntimeResult{Artifact: a, Status: "inconclusive", Limitations: []string{"External runtime egress disabled; delayed or remotely gated payloads may not activate", "A quiet sandbox run does not prove safety", "Only the configured Linux sandbox platform is exercised"}}
	check := a.Package
	check.SHA256 = a.SHA256
	if err := check.Normalize(); err != nil || len(a.SHA256) != 64 {
		out.Limitations = append(out.Limitations, "Invalid runtime artifact identity or sha256")
		return out
	}
	image := r.Config.SandboxImages[strings.ToLower(a.Package.Ecosystem)]
	if !pinnedImage(image) || r.Config.SandboxRuntime != "runsc" {
		out.Limitations = append(out.Limitations, "Configure a digest-pinned sandbox image and runsc runtime")
		return out
	}
	if err := os.MkdirAll(r.Dir, 0700); err != nil {
		out.Limitations = append(out.Limitations, err.Error())
		return out
	}
	dir, err := os.MkdirTemp(r.Dir, "sandbox-")
	if err != nil {
		out.Limitations = append(out.Limitations, err.Error())
		return out
	}
	defer os.RemoveAll(dir)
	c := netfetch.New([]string{"registry.npmjs.org", "pypi.org", "files.pythonhosted.org"}, "")
	res, err := c.Get(ctx, a.URL, r.Config.MaxArtifactBytes, "")
	if err != nil {
		out.Limitations = append(out.Limitations, err.Error())
		return out
	}
	if model.Hash(res.Body) != a.SHA256 {
		out.Limitations = append(out.Limitations, "Runtime artifact hash mismatch")
		return out
	}
	deps := filepath.Join(dir, "deps")
	if err = os.MkdirAll(deps, 0700); err != nil {
		out.Limitations = append(out.Limitations, err.Error())
		return out
	}
	w := Worker{Client: c, Config: r.Config}
	limitations, err := w.Prefetch(ctx, a, res.Body, deps)
	out.Limitations = append(out.Limitations, limitations...)
	if err != nil {
		out.Limitations = append(out.Limitations, err.Error())
		return out
	}
	filename := a.Filename
	if !safeName(filename) || strings.Contains(filename, "/") {
		out.Limitations = append(out.Limitations, "Invalid artifact filename")
		return out
	}
	if err = os.WriteFile(filepath.Join(dir, filename), res.Body, 0600); err != nil {
		out.Limitations = append(out.Limitations, err.Error())
		return out
	}
	// Inputs contain archives only, never credentials or a host filesystem mount.
	if err = makeReadable(dir); err != nil {
		out.Limitations = append(out.Limitations, err.Error())
		return out
	}
	runCtx, cancel := context.WithTimeout(ctx, r.Config.RuntimeTimeout)
	defer cancel()
	name := "zoli-analysis-" + a.SHA256[:16] + fmt.Sprintf("-%d", time.Now().UnixNano())
	args := []string{"create", "--name", name, "--runtime=runsc", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=512m", "--cpus=1", "--pids-limit=128", "--ulimit=nofile=256:256", "--tmpfs=/tmp:rw,nosuid,nodev,size=128m,mode=1777", "--tmpfs=/work:rw,nosuid,nodev,size=384m,mode=1777", "--env=AWS_SECRET_ACCESS_KEY=ZOLI_SYNTHETIC_SECRET", "--env=NPM_TOKEN=ZOLI_SYNTHETIC_TOKEN", "--env=ZOLI_ARTIFACT=" + filename, image}
	if _, err = command(runCtx, "podman", args...); err != nil {
		out.Limitations = append(out.Limitations, "Sandbox creation failed: "+err.Error())
		return out
	}
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command(cleanCtx, "podman", "rm", "--force", name)
	}()
	idOutput, err := command(runCtx, "podman", "inspect", "--format={{.Id}}", name)
	containerID := regexp.MustCompile(`(?m)^[a-f0-9]{64}$`).FindString(string(idOutput))
	if err != nil || containerID == "" {
		out.Limitations = append(out.Limitations, "Unable to identify sandbox telemetry")
		return out
	}
	if _, err = command(runCtx, "podman", "cp", dir+"/.", name+":/input/"); err != nil {
		out.Limitations = append(out.Limitations, "Sandbox input copy failed")
		return out
	}
	_, runErr := command(runCtx, "podman", "start", "--attach", name)
	if runCtx.Err() != nil {
		killCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		command(killCtx, "podman", "kill", name)
		out.Limitations = append(out.Limitations, "Sandbox timeout")
	}
	tracePath := filepath.Join(r.Config.SandboxTraceDir, containerID+".boot.log")
	f, err := os.Open(tracePath)
	if err != nil {
		out.Limitations = append(out.Limitations, "Host-side gVisor telemetry unavailable; configure the supplied runsc wrapper")
		return out
	}
	trace, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	f.Close()
	if err != nil || len(trace) > 8<<20 {
		out.Limitations = append(out.Limitations, "Telemetry size limit exceeded")
		return out
	}
	out.TraceSHA256 = model.Hash(trace)
	traceDir := filepath.Join(r.Dir, "traces")
	if err = os.MkdirAll(traceDir, 0700); err != nil {
		out.Limitations = append(out.Limitations, "Private telemetry retention failed")
		return out
	}
	if err = os.WriteFile(filepath.Join(traceDir, out.TraceSHA256+".log"), trace, 0600); err != nil {
		out.Limitations = append(out.Limitations, "Private telemetry retention failed")
		return out
	}
	configBytes, _ := json.Marshal(r.Config)
	if err = os.WriteFile(filepath.Join(traceDir, out.TraceSHA256+".config.json"), configBytes, 0600); err != nil {
		out.Limitations = append(out.Limitations, "Private configuration retention failed")
		return out
	}
	observations := []string{}
	if regexp.MustCompile(`openat\([^\n]*(\.aws/(credentials|config)|\.ssh/id_rsa)[^\n]*(O_RDONLY|O_RDWR)`).Match(trace) {
		observations = append(observations, "Access to synthetic credential path observed")
	}
	if regexp.MustCompile(`connect\([^\n]*(AF_INET|AF_INET6)`).Match(trace) {
		observations = append(observations, "Network connection attempted with external egress disabled")
	}
	if regexp.MustCompile(`execve\(`).Match(trace) {
		observations = append(observations, "Process execution observed")
	}
	exitOutput, exitErr := command(ctx, "podman", "inspect", "--format={{.State.ExitCode}}", name)
	if runErr != nil || exitErr != nil || strings.TrimSpace(string(exitOutput)) != "0" {
		out.Limitations = append(out.Limitations, "Installation or package load failed; telemetry covers partial execution")
	} else {
		out.Status = "observed"
	}
	if len(observations) > 0 {
		out.Evidence = []model.Evidence{{RuleID: "ZOLI-RUNTIME-001", RuleVersion: "1.0.0", ArtifactSHA256: a.SHA256, Explanation: "Observed runtime capabilities; operator review required", Observations: observations, Reproduce: "zoli-intel runner --config <same digest-pinned sandbox configuration>", Limitations: out.Limitations}}
	}
	return out
}
func pinnedImage(s string) bool {
	return regexp.MustCompile(`^(?:[a-zA-Z0-9./:_-]+@)?sha256:[a-f0-9]{64}$`).MatchString(s)
}
func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "XDG_RUNTIME_DIR=" + os.Getenv("XDG_RUNTIME_DIR")}
	var b limitedBuffer
	b.limit = 1 << 20
	cmd.Stdout = &b
	cmd.Stderr = &b
	err := cmd.Run()
	if err != nil {
		return b.Bytes(), fmt.Errorf("%s: %w", name, err)
	}
	return b.Bytes(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remain := b.limit - b.Len()
	if remain > 0 {
		if len(p) > remain {
			p = p[:remain]
		}
		b.Buffer.Write(p)
	}
	return n, nil
}
func makeReadable(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if info.IsDir() {
			mode = 0755
		}
		return os.Chmod(path, mode)
	})
}
