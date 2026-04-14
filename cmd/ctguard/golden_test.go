package main

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

func TestGolden(t *testing.T) {
	// Build the ctguard binary first
	exe := buildTestBinary(t)
	defer func() { _ = os.Remove(exe) }()

	projectRoot := getProjectRoot(t)
	goldenDir := filepath.Join(projectRoot, "testdata", "golden", "expected")

	// Ensure golden directory exists
	if err := os.MkdirAll(goldenDir, 0755); err != nil {
		t.Fatalf("failed to create golden dir: %v", err)
	}

	// Use testdata/src/ which contains stable test fixtures
	// These are the same packages used by analysistest
	cases := []struct {
		name       string
		target     string // relative to project root
		args       []string
		goldenFile string
	}{
		// Package 'branches' - CT001 (secret-dependent branches)
		{
			name:       "branches_plain",
			target:     "./testdata/src/branches/",
			args:       []string{},
			goldenFile: "branches.plain.golden",
		},
		{
			name:       "branches_json",
			target:     "./testdata/src/branches/",
			args:       []string{"-format=json"},
			goldenFile: "branches.json.golden",
		},
		{
			name:       "branches_sarif",
			target:     "./testdata/src/branches/",
			args:       []string{"-format=sarif"},
			goldenFile: "branches.sarif.golden",
		},
		// Package 'comparisons' - CT002 (non-constant-time comparisons)
		{
			name:       "comparisons_plain",
			target:     "./testdata/src/comparisons/",
			args:       []string{},
			goldenFile: "comparisons.plain.golden",
		},
		{
			name:       "comparisons_json",
			target:     "./testdata/src/comparisons/",
			args:       []string{"-format=json"},
			goldenFile: "comparisons.json.golden",
		},
		{
			name:       "comparisons_sarif",
			target:     "./testdata/src/comparisons/",
			args:       []string{"-format=sarif"},
			goldenFile: "comparisons.sarif.golden",
		},
		// Package 'nested' - nested branches
		{
			name:       "nested_plain",
			target:     "./testdata/src/nested/",
			args:       []string{},
			goldenFile: "nested.plain.golden",
		},
		// Package 'propagation' - taint propagation
		{
			name:       "propagation_plain",
			target:     "./testdata/src/propagation/",
			args:       []string{},
			goldenFile: "propagation.plain.golden",
		},
		// Package 'edge' - edge cases (multiple rules)
		{
			name:       "edge_plain",
			target:     "./testdata/src/edge/",
			args:       []string{},
			goldenFile: "edge.plain.golden",
		},
		{
			name:       "edge_json",
			target:     "./testdata/src/edge/",
			args:       []string{"-format=json"},
			goldenFile: "edge.json.golden",
		},
		{
			name:       "edge_sarif",
			target:     "./testdata/src/edge/",
			args:       []string{"-format=sarif"},
			goldenFile: "edge.sarif.golden",
		},
		// Package 'clean' - no issues expected
		{
			name:       "clean_plain",
			target:     "./testdata/src/clean/",
			args:       []string{},
			goldenFile: "clean.plain.golden",
		},
		// Package 'indexing' - CT003 (secret-dependent indexing)
		{
			name:       "indexing_plain",
			target:     "./testdata/src/indexing/",
			args:       []string{},
			goldenFile: "indexing.plain.golden",
		},
		{
			name:       "indexing_json",
			target:     "./testdata/src/indexing/",
			args:       []string{"-format=json"},
			goldenFile: "indexing.json.golden",
		},
		{
			name:       "indexing_sarif",
			target:     "./testdata/src/indexing/",
			args:       []string{"-format=sarif"},
			goldenFile: "indexing.sarif.golden",
		},
		// Rule filtering
		{
			name:       "edge_ct001_only",
			target:     "./testdata/src/edge/",
			args:       []string{"-rules=CT001"},
			goldenFile: "edge.ct001.golden",
		},
		{
			name:       "edge_ct002_only",
			target:     "./testdata/src/edge/",
			args:       []string{"-rules=CT002"},
			goldenFile: "edge.ct002.golden",
		},
		{
			name:       "indexing_ct003_only",
			target:     "./testdata/src/indexing/",
			args:       []string{"-rules=CT003"},
			goldenFile: "indexing.ct003.golden",
		},
		// CT004 tests
		{
			name:       "exposure_plain",
			target:     "./testdata/src/exposure/",
			args:       []string{},
			goldenFile: "exposure.plain.golden",
		},
		{
			name:       "exposure_json",
			target:     "./testdata/src/exposure/",
			args:       []string{"-format=json"},
			goldenFile: "exposure.json.golden",
		},
		{
			name:       "exposure_sarif",
			target:     "./testdata/src/exposure/",
			args:       []string{"-format=sarif"},
			goldenFile: "exposure.sarif.golden",
		},
		{
			name:       "exposure_ct004_only",
			target:     "./testdata/src/exposure/",
			args:       []string{"-rules=CT004"},
			goldenFile: "exposure.ct004.golden",
		},
		// Package 'arithmetic' - CT005 (variable-time arithmetic)
		{
			name:       "arithmetic_plain",
			target:     "./testdata/src/arithmetic/",
			args:       []string{},
			goldenFile: "arithmetic.plain.golden",
		},
		{
			name:       "arithmetic_json",
			target:     "./testdata/src/arithmetic/",
			args:       []string{"-format=json"},
			goldenFile: "arithmetic.json.golden",
		},
		{
			name:       "arithmetic_sarif",
			target:     "./testdata/src/arithmetic/",
			args:       []string{"-format=sarif"},
			goldenFile: "arithmetic.sarif.golden",
		},
		{
			name:       "arithmetic_ct005_only",
			target:     "./testdata/src/arithmetic/",
			args:       []string{"-rules=CT005"},
			goldenFile: "arithmetic.ct005.golden",
		},
		// Ignore annotation tests
		{
			name:       "ignores_plain",
			target:     "./testdata/src/ignores/",
			args:       []string{},
			goldenFile: "ignores.plain.golden",
		},
		{
			name:       "ignores_json",
			target:     "./testdata/src/ignores/",
			args:       []string{"-format=json"},
			goldenFile: "ignores.json.golden",
		},
		// Package 'channels' - CT006 (channel operations with secret data)
		{
			name:       "channels_plain",
			target:     "./testdata/src/channels/",
			args:       []string{},
			goldenFile: "channels.plain.golden",
		},
		{
			name:       "channels_json",
			target:     "./testdata/src/channels/",
			args:       []string{"-format=json"},
			goldenFile: "channels.json.golden",
		},
		{
			name:       "channels_sarif",
			target:     "./testdata/src/channels/",
			args:       []string{"-format=sarif"},
			goldenFile: "channels.sarif.golden",
		},
		{
			name:       "channels_ct006_only",
			target:     "./testdata/src/channels/",
			args:       []string{"-rules=CT006"},
			goldenFile: "channels.ct006.golden",
		},
		// Package 'isolated' - CT007 (secret data in I/O sinks within isolated regions)
		{
			name:       "isolated_plain",
			target:     "./testdata/src/isolated/",
			args:       []string{},
			goldenFile: "isolated.plain.golden",
		},
		{
			name:       "isolated_sarif",
			target:     "./testdata/src/isolated/",
			args:       []string{"-format=sarif"},
			goldenFile: "isolated.sarif.golden",
		},
		{
			name:       "isolated_ct007_only",
			target:     "./testdata/src/isolated/",
			args:       []string{"-rules=CT007"},
			goldenFile: "isolated.ct007.golden",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			goldenPath := filepath.Join(goldenDir, tc.goldenFile)

			// Build args: custom args + target
			args := append([]string{"-fail=false", "-summary=false"}, tc.args...)
			args = append(args, tc.target)

			// Run ctguard from project root
			actual := runCtguard(t, exe, projectRoot, args)

			// Normalize output for comparison
			actual = normalizeOutput(actual, projectRoot)

			if *update {
				if err := os.WriteFile(goldenPath, []byte(actual), 0644); err != nil {
					t.Fatalf("failed to write golden file: %v", err)
				}
				t.Logf("updated golden file: %s", goldenPath)
				return
			}

			expected, err := os.ReadFile(goldenPath)
			if err != nil {
				if os.IsNotExist(err) {
					t.Fatalf("golden file not found: %s\nRun with -update to create it", goldenPath)
				}
				t.Fatalf("failed to read golden file: %v", err)
			}

			if diff := diffStrings(string(expected), actual); diff != "" {
				t.Errorf("output mismatch for %s:\n%s", tc.name, diff)
			}
		})
	}
}

func buildTestBinary(t *testing.T) string {
	t.Helper()

	// Create temp file for binary
	tmpFile, err := os.CreateTemp("", "ctguard-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	_ = tmpFile.Close()
	exe := tmpFile.Name()

	// Build the binary
	cmd := exec.Command("go", "build", "-o", exe, ".")
	cmd.Dir = filepath.Join(getProjectRoot(t), "cmd", "ctguard")

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build ctguard: %v\nstderr: %s", err, stderr.String())
	}

	return exe
}

func getProjectRoot(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to locate test file path")
	}

	// This file is at cmd/ctguard/main_test.go
	// Project root is ../../
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

func runCtguard(t *testing.T, exe string, workDir string, args []string) string {
	t.Helper()

	// Create a temporary empty config to prevent .ctguard.yaml from being loaded
	tmpConfig, err := os.CreateTemp("", "ctguard-test-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}
	defer func() { _ = os.Remove(tmpConfig.Name()) }()
	_, _ = tmpConfig.WriteString("# Empty test config\n")
	_ = tmpConfig.Close()

	// Prepend -config flag to args
	testArgs := append([]string{"-config=" + tmpConfig.Name()}, args...)

	cmd := exec.Command(exe, testArgs...)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), "NO_COLOR=1")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// We ignore exit code since ctguard may exit non-zero on findings
	_ = cmd.Run()

	// Combine stdout and stderr for full output
	output := stdout.String()
	if stderr.Len() > 0 {
		output += stderr.String()
	}

	return output
}

// normalizeOutput removes absolute paths and other variable content
func normalizeOutput(output string, workDir string) string {
	// Remove the working directory prefix from paths
	output = strings.ReplaceAll(output, workDir+"/", "")
	output = strings.ReplaceAll(output, workDir, ".")

	// Normalize tool version in SARIF output (version can vary between builds)
	// SARIF schema version is exactly "2.1.0" at top level
	// Tool version appears after "name": "ctguard" in the driver section
	toolVersionRegex := regexp.MustCompile(`("name": "ctguard",\n\s+"version": )"[^"]+"`)
	output = toolVersionRegex.ReplaceAllString(output, `$1"<VERSION>"`)

	// Normalize any remaining absolute paths that might leak through
	// Match patterns like /Users/xxx/... or /home/xxx/...
	absPathRegex := regexp.MustCompile(`(/Users/[^/]+|/home/[^/]+|/tmp/[^/]+)[^\s:]*`)
	output = absPathRegex.ReplaceAllStringFunc(output, func(match string) string {
		// Keep just the relative part after common prefixes
		parts := strings.Split(match, "/")
		if len(parts) > 3 {
			// Try to find testdata or cases in the path
			for i, p := range parts {
				if p == "testdata" || p == "cases" {
					return strings.Join(parts[i:], "/")
				}
			}
		}
		return match
	})

	// Trim trailing whitespace from each line
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	output = strings.Join(lines, "\n")

	// Ensure consistent line endings
	output = strings.ReplaceAll(output, "\r\n", "\n")

	return output
}

// diffStrings provides a simple line-by-line diff
func diffStrings(expected, actual string) string {
	if expected == actual {
		return ""
	}

	var diff strings.Builder
	expectedLines := strings.Split(expected, "\n")
	actualLines := strings.Split(actual, "\n")

	maxLines := len(expectedLines)
	if len(actualLines) > maxLines {
		maxLines = len(actualLines)
	}

	diff.WriteString("--- expected\n+++ actual\n")

	for i := 0; i < maxLines; i++ {
		var expLine, actLine string
		if i < len(expectedLines) {
			expLine = expectedLines[i]
		}
		if i < len(actualLines) {
			actLine = actualLines[i]
		}

		if expLine != actLine {
			if expLine != "" {
				diff.WriteString("- " + expLine + "\n")
			}
			if actLine != "" {
				diff.WriteString("+ " + actLine + "\n")
			}
		}
	}

	return diff.String()
}

// TestCLIFlags tests specific CLI flag behaviors
func TestCLIFlags(t *testing.T) {
	exe := buildTestBinary(t)
	defer func() { _ = os.Remove(exe) }()

	t.Run("help_flag", func(t *testing.T) {
		cmd := exec.Command(exe, "--help")
		output, _ := cmd.CombinedOutput()
		if !strings.Contains(string(output), "CTGuard") {
			t.Error("help output should contain CTGuard")
		}
		if !strings.Contains(string(output), "-format") {
			t.Error("help output should contain -format flag")
		}
	})

	t.Run("version_flag", func(t *testing.T) {
		cmd := exec.Command(exe, "--version")
		output, _ := cmd.CombinedOutput()
		if !strings.Contains(string(output), "ctguard") {
			t.Error("version output should contain ctguard")
		}
	})

	t.Run("invalid_format", func(t *testing.T) {
		cmd := exec.Command(exe, "-format=xml", "./...")
		cmd.Dir = getProjectRoot(t)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err == nil {
			t.Error("expected error for invalid format")
		}
		if !strings.Contains(stderr.String(), "plain") || !strings.Contains(stderr.String(), "json") {
			t.Errorf("error should mention valid formats, got: %s", stderr.String())
		}
	})
}
