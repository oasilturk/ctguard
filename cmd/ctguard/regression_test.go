package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// mergeEnv overrides parent entries by key so a test-provided GOCACHE wins over
// any inherited one.
func mergeEnv(parent []string, overrides ...string) []string {
	keys := make(map[string]bool, len(overrides))
	for _, o := range overrides {
		if i := strings.IndexByte(o, '='); i > 0 {
			keys[o[:i]] = true
		}
	}
	out := make([]string, 0, len(parent)+len(overrides))
	for _, e := range parent {
		if i := strings.IndexByte(e, '='); i > 0 && keys[e[:i]] {
			continue
		}
		out = append(out, e)
	}
	return append(out, overrides...)
}

// writeTempConfig writes content to a temp YAML file and returns its path.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	return path
}

// runForFindings runs the ctguard CLI in JSON mode and returns the decoded findings.
func runForFindings(t *testing.T, exe, projectRoot string, extraEnv []string, args ...string) []Finding {
	t.Helper()

	full := append([]string{"-format=json", "-fail=false", "-summary=false"}, args...)
	cmd := exec.Command(exe, full...)
	cmd.Dir = projectRoot
	cmd.Env = mergeEnv(os.Environ(), append([]string{"NO_COLOR=1"}, extraEnv...)...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run() // non-zero exit can be normal; we assert on decoded findings

	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) == 0 || string(out) == "null" {
		return nil
	}
	var findings []Finding
	if err := json.Unmarshal(out, &findings); err != nil {
		t.Fatalf("failed to decode findings JSON: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	return findings
}

// TestRegressionBugA_FindingsSurfaced guards Bug A: the CLI must surface findings
// (the wrapper used to parse only stderr, dropping everything under Go 1.26).
func TestRegressionBugA_FindingsSurfaced(t *testing.T) {
	exe := buildTestBinary(t)
	defer func() { _ = os.Remove(exe) }()
	root := getProjectRoot(t)

	// Empty config so the project .ctguard.yaml exclude doesn't filter testdata.
	emptyCfg := writeTempConfig(t, "# empty\n")

	cases := []struct {
		name   string
		target string
	}{
		{"comparisons_CT002", "./testdata/src/comparisons/"},
		{"branches_CT001", "./testdata/src/branches/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := runForFindings(t, exe, root, nil, "-config="+emptyCfg, tc.target)
			if len(findings) == 0 {
				t.Fatalf("expected >0 findings for %s, got 0 (Bug A: go vet -json stream not parsed)", tc.target)
			}
		})
	}
}
