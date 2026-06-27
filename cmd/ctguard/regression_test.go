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

// writeModuleFile writes content to path (relative to root), creating parent dirs.
func writeModuleFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// Regression: a broken package must not drop a healthy sibling's findings or pass clean.
func TestRegressionFailOpen_BuildError(t *testing.T) {
	exe := buildTestBinary(t)
	defer func() { _ = os.Remove(exe) }()

	mod := t.TempDir()
	writeModuleFile(t, mod, "go.mod", "module ctgfailopen\n\ngo 1.25\n")
	writeModuleFile(t, mod, "broken/broken.go", "package broken\n\nfunc Oops( {\n")
	writeModuleFile(t, mod, "fires/fires.go",
		"package fires\n\n//ctguard:secret password\n"+
			"func Login(password, stored string) bool {\n"+
			"\tif password == stored {\n\t\treturn true\n\t}\n\treturn false\n}\n")

	emptyCfg := writeTempConfig(t, "# empty\n")

	cmd := exec.Command(exe, "-format=json", "-summary=false", "-config="+emptyCfg, "./...")
	cmd.Dir = mod
	cmd.Env = mergeEnv(os.Environ(), "NO_COLOR=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	if !strings.Contains(stdout.String(), "CT001") {
		t.Fatalf("fail-open: the healthy package's finding was dropped because a sibling failed to compile\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	}
	if exitCodeFromErr(err) == 0 {
		t.Errorf("expected non-zero exit for an incomplete scan, got 0\nstderr:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "failed to load") {
		t.Errorf("expected a build-failure notice on stderr, got:\n%s", stderr.String())
	}
}

// Regression: a malformed //ctguard:ignore (typo/prose) must not silence findings.
func TestRegressionMalformedIgnoreFailsClosed(t *testing.T) {
	exe := buildTestBinary(t)
	defer func() { _ = os.Remove(exe) }()

	mod := t.TempDir()
	writeModuleFile(t, mod, "go.mod", "module ctgignore\n\ngo 1.25\n")
	writeModuleFile(t, mod, "x/x.go",
		"package x\n\n//ctguard:secret pw\n"+
			"func Login(pw, stored string) bool {\n"+
			"\tif pw == stored { //ctguard:ignore needed for legacy\n"+
			"\t\treturn true\n\t}\n\treturn false\n}\n")
	emptyCfg := writeTempConfig(t, "# empty\n")

	findings := runForFindings(t, exe, mod, nil, "-config="+emptyCfg, "./x/")
	if len(findings) == 0 {
		t.Fatal("fail-open: a malformed //ctguard:ignore silenced all findings")
	}
}

// Regression: an unknown rule ID must exit 2, not silently pass clean.
func TestRegressionUnknownRuleExits2(t *testing.T) {
	exe := buildTestBinary(t)
	defer func() { _ = os.Remove(exe) }()
	root := getProjectRoot(t)
	emptyCfg := writeTempConfig(t, "# empty\n")

	cmd := exec.Command(exe, "-rules=CT2", "-config="+emptyCfg, "./testdata/src/branches/")
	cmd.Dir = root
	cmd.Env = mergeEnv(os.Environ(), "NO_COLOR=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	if got := exitCodeFromErr(err); got != 2 {
		t.Errorf("expected exit 2 for unknown rule, got %d (stderr: %s)", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "unknown rule") {
		t.Errorf("expected 'unknown rule' error, got: %s", stderr.String())
	}
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
