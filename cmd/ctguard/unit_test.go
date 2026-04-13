package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/oasilturk/ctguard/internal/confidence"
)

func TestExtractRule(t *testing.T) {
	tests := []struct {
		msg  string
		want string
	}{
		{"CT001: branch depends on secret 'key'", "CT001"},
		{"CT002: non-constant-time comparison", "CT002"},
		{"CT007: secret flows into I/O sink", "CT007"},
		{"no colon here", ""},
		{"", ""},
		{"notCT: something", ""},
		{"CT001 missing colon", ""},
	}
	for _, tt := range tests {
		if got := extractRule(tt.msg); got != tt.want {
			t.Errorf("extractRule(%q) = %q, want %q", tt.msg, got, tt.want)
		}
	}
}

func TestExtractConfidence(t *testing.T) {
	tests := []struct {
		msg  string
		want string
	}{
		{"CT001: branch depends on secret 'key' (confidence: high)", "high"},
		{"CT002: comparison (confidence: low)", "low"},
		{"CT001: no confidence tag", ""},
		{"", ""},
		{"(confidence: high) at the start", "high"},
	}
	for _, tt := range tests {
		if got := extractConfidence(tt.msg); got != tt.want {
			t.Errorf("extractConfidence(%q) = %q, want %q", tt.msg, got, tt.want)
		}
	}
}

func TestEnabledRuleSet(t *testing.T) {
	tests := []struct {
		input string
		want  map[string]bool
	}{
		{"all", map[string]bool{}},
		{"ALL", map[string]bool{}},
		{"*", map[string]bool{}},
		{"", map[string]bool{}},
		{"  ", map[string]bool{}},
		{"CT001", map[string]bool{"CT001": true}},
		{"CT001,CT003", map[string]bool{"CT001": true, "CT003": true}},
		{"ct001, ct003", map[string]bool{"CT001": true, "CT003": true}},
		{"CT001,,CT003", map[string]bool{"CT001": true, "CT003": true}},
	}
	for _, tt := range tests {
		got := enabledRuleSet(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("enabledRuleSet(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for k, v := range tt.want {
			if got[k] != v {
				t.Errorf("enabledRuleSet(%q)[%s] = %v, want %v", tt.input, k, got[k], v)
			}
		}
	}
}

func TestFilterFindings(t *testing.T) {
	findings := []Finding{
		{Rule: "CT001", Message: "CT001: branch (confidence: high)", Confidence: "high"},
		{Rule: "CT002", Message: "CT002: compare (confidence: low)", Confidence: "low"},
		{Rule: "CT003", Message: "CT003: index (confidence: high)", Confidence: "high"},
		{Rule: "", Message: "unknown finding"},
	}

	t.Run("no_filter", func(t *testing.T) {
		got := filterFindings(findings, map[string]bool{}, confidence.ConfidenceLow)
		if len(got) != 4 {
			t.Errorf("expected 4 findings, got %d", len(got))
		}
	})

	t.Run("rule_filter", func(t *testing.T) {
		enabled := map[string]bool{"CT001": true}
		got := filterFindings(findings, enabled, confidence.ConfidenceLow)
		if len(got) != 1 || got[0].Rule != "CT001" {
			t.Errorf("expected only CT001, got %v", got)
		}
	})

	t.Run("multi_rule_filter", func(t *testing.T) {
		enabled := map[string]bool{"CT001": true, "CT003": true}
		got := filterFindings(findings, enabled, confidence.ConfidenceLow)
		if len(got) != 2 {
			t.Errorf("expected 2 findings, got %d", len(got))
		}
	})

	t.Run("confidence_high_only", func(t *testing.T) {
		got := filterFindings(findings, map[string]bool{}, confidence.ConfidenceHigh)
		if len(got) != 2 {
			t.Errorf("expected 2 high-confidence findings, got %d", len(got))
		}
		for _, f := range got {
			if f.Confidence != "high" {
				t.Errorf("expected high confidence, got %q", f.Confidence)
			}
		}
	})

	t.Run("rule_and_confidence", func(t *testing.T) {
		enabled := map[string]bool{"CT001": true, "CT002": true}
		got := filterFindings(findings, enabled, confidence.ConfidenceHigh)
		if len(got) != 1 || got[0].Rule != "CT001" {
			t.Errorf("expected only CT001 (high), got %v", got)
		}
	})

	t.Run("empty_input", func(t *testing.T) {
		got := filterFindings(nil, map[string]bool{"CT001": true}, confidence.ConfidenceLow)
		if len(got) != 0 {
			t.Errorf("expected 0 findings, got %d", len(got))
		}
	})

	t.Run("no_rule_filtered_out", func(t *testing.T) {
		enabled := map[string]bool{"CT001": true}
		got := filterFindings(findings, enabled, confidence.ConfidenceLow)
		for _, f := range got {
			if f.Rule == "" {
				t.Error("finding with empty rule should be filtered when rules are specified")
			}
		}
	})
}

func TestShouldExclude(t *testing.T) {
	tests := []struct {
		name     string
		pos      string
		patterns []string
		want     bool
	}{
		{"empty_pos", "", []string{"vendor/**"}, false},
		{"empty_patterns", "foo.go:1:1", nil, false},
		{"vendor_glob", "vendor/lib/foo.go:10:5", []string{"vendor/**"}, true},
		{"test_glob", "pkg/foo_test.go:5:1", []string{"*_test.go"}, true},
		{"no_match", "internal/analyzer.go:1:1", []string{"vendor/**"}, false},
		{"star_glob", "generated.pb.go:1:1", []string{"*.pb.go"}, true},
		{"exact_prefix", "vendor/lib.go:1:1", []string{"vendor"}, true},
		{"empty_pattern_in_list", "foo.go:1:1", []string{"", "  "}, false},
		{"quoted_pattern", "vendor/lib/foo.go:10:5", []string{`"vendor/**"`}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldExclude(tt.pos, tt.patterns); got != tt.want {
				t.Errorf("shouldExclude(%q, %v) = %v, want %v", tt.pos, tt.patterns, got, tt.want)
			}
		})
	}
}

func TestFilterExcludedPaths(t *testing.T) {
	findings := []Finding{
		{Pos: "internal/main.go:1:1", Rule: "CT001"},
		{Pos: "vendor/lib/foo.go:5:1", Rule: "CT002"},
		{Pos: "pkg/foo_test.go:10:1", Rule: "CT003"},
	}

	t.Run("no_patterns", func(t *testing.T) {
		got := filterExcludedPaths(findings, nil)
		if len(got) != 3 {
			t.Errorf("expected 3, got %d", len(got))
		}
	})

	t.Run("exclude_vendor", func(t *testing.T) {
		got := filterExcludedPaths(findings, []string{"vendor/**"})
		if len(got) != 2 {
			t.Errorf("expected 2, got %d", len(got))
		}
	})

	t.Run("exclude_vendor_and_tests", func(t *testing.T) {
		got := filterExcludedPaths(findings, []string{"vendor/**", "*_test.go"})
		if len(got) != 1 {
			t.Errorf("expected 1, got %d", len(got))
		}
		if got[0].Rule != "CT001" {
			t.Errorf("expected CT001, got %s", got[0].Rule)
		}
	})
}

func TestExtractJSONObjects(t *testing.T) {
	tests := []struct {
		name  string
		input string
		count int
	}{
		{"empty", "", 0},
		{"single", `{"key": "value"}`, 1},
		{"two_objects", "# pkg1\n{\"a\":1}\n# pkg2\n{\"b\":2}\n", 2},
		{"nested", `{"outer": {"inner": "val"}}`, 1},
		{"no_json", "just some text\nno braces", 0},
		{"with_prefix_text", "# some/pkg\n{\"data\": true}\n", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJSONObjects(tt.input)
			if len(got) != tt.count {
				t.Errorf("extractJSONObjects() returned %d objects, want %d", len(got), tt.count)
			}
		})
	}
}

func TestParseGoVetJSON(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		got := parseGoVetJSON("")
		if len(got) != 0 {
			t.Errorf("expected 0 findings, got %d", len(got))
		}
	})

	t.Run("single_finding", func(t *testing.T) {
		input := `{
			"example.com/pkg": {
				"ctguard": [
					{"posn": "file.go:10:5", "message": "CT001: branch depends on secret 'key' (confidence: high)"}
				]
			}
		}`
		got := parseGoVetJSON(input)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
		if got[0].Rule != "CT001" {
			t.Errorf("expected rule CT001, got %q", got[0].Rule)
		}
		if got[0].Confidence != "high" {
			t.Errorf("expected confidence high, got %q", got[0].Confidence)
		}
		if got[0].Pos != "file.go:10:5" {
			t.Errorf("expected pos file.go:10:5, got %q", got[0].Pos)
		}
	})

	t.Run("multiple_packages", func(t *testing.T) {
		input := `{"pkg1": {"ctguard": [{"posn": "a.go:1:1", "message": "CT001: x (confidence: high)"}]}}
{"pkg2": {"ctguard": [{"posn": "b.go:2:1", "message": "CT002: y (confidence: low)"}]}}`
		got := parseGoVetJSON(input)
		if len(got) != 2 {
			t.Errorf("expected 2 findings, got %d", len(got))
		}
	})

	t.Run("malformed_json", func(t *testing.T) {
		got := parseGoVetJSON("not json at all {{{")
		if len(got) != 0 {
			t.Errorf("expected 0 findings for malformed input, got %d", len(got))
		}
	})

	t.Run("pos_fallback", func(t *testing.T) {
		input := `{"pkg": {"ctguard": [{"pos": "fallback.go:1:1", "message": "CT001: test (confidence: low)"}]}}`
		got := parseGoVetJSON(input)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
		if got[0].Pos != "fallback.go:1:1" {
			t.Errorf("expected pos from 'pos' field, got %q", got[0].Pos)
		}
	})

	t.Run("empty_message_skipped", func(t *testing.T) {
		input := `{"pkg": {"ctguard": [{"posn": "a.go:1:1", "message": ""}]}}`
		got := parseGoVetJSON(input)
		if len(got) != 0 {
			t.Errorf("expected 0 findings for empty message, got %d", len(got))
		}
	})
}

func TestExitCodeFromErr(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if got := exitCodeFromErr(nil); got != 0 {
			t.Errorf("expected 0, got %d", got)
		}
	})

	t.Run("exit_error", func(t *testing.T) {
		// Create a real ExitError by running a command that fails
		cmd := exec.Command("sh", "-c", "exit 42")
		err := cmd.Run()
		if got := exitCodeFromErr(err); got != 42 {
			t.Errorf("expected 42, got %d", got)
		}
	})

	t.Run("other_error", func(t *testing.T) {
		err := exec.Command("nonexistent-binary-12345").Run()
		if got := exitCodeFromErr(err); got != 1 {
			t.Errorf("expected 1 for non-ExitError, got %d", got)
		}
	})
}

// captureStdout runs fn and returns what it wrote to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestPrintPlain(t *testing.T) {
	// Disable colors for deterministic output
	oldC := c
	c = colors{}
	defer func() { c = oldC }()

	t.Run("with_findings", func(t *testing.T) {
		findings := []Finding{
			{Pos: "auth.go:10:5", Rule: "CT001", Message: "CT001: branch depends on secret 'key'"},
			{Pos: "crypto.go:20:3", Rule: "CT002", Message: "CT002: non-constant-time comparison"},
		}
		out := captureStdout(t, func() { printPlain(findings) })
		if !strings.Contains(out, "CT001") {
			t.Errorf("expected CT001 in output, got: %s", out)
		}
		if !strings.Contains(out, "CT002") {
			t.Errorf("expected CT002 in output, got: %s", out)
		}
		if !strings.Contains(out, "branch depends on secret") {
			t.Errorf("expected message in output, got: %s", out)
		}
	})

	t.Run("empty_findings", func(t *testing.T) {
		out := captureStdout(t, func() { printPlain(nil) })
		if out != "" {
			t.Errorf("expected empty output for nil findings, got: %q", out)
		}
	})

	t.Run("no_pos", func(t *testing.T) {
		findings := []Finding{
			{Rule: "CT001", Message: "CT001: something"},
		}
		out := captureStdout(t, func() { printPlain(findings) })
		if !strings.Contains(out, "CT001") {
			t.Errorf("expected CT001 in output, got: %s", out)
		}
	})

	t.Run("unknown_rule", func(t *testing.T) {
		findings := []Finding{
			{Pos: "file.go:1:1", Message: "unknown issue"},
		}
		out := captureStdout(t, func() { printPlain(findings) })
		if !strings.Contains(out, "???") {
			t.Errorf("expected ??? for empty rule, got: %s", out)
		}
	})

	t.Run("all_rule_colors", func(t *testing.T) {
		rules := []string{"CT001", "CT002", "CT003", "CT004", "CT005", "CT006", "CT007"}
		for _, rule := range rules {
			findings := []Finding{
				{Pos: "f.go:1:1", Rule: rule, Message: rule + ": test"},
			}
			out := captureStdout(t, func() { printPlain(findings) })
			if !strings.Contains(out, rule) {
				t.Errorf("expected %s in output, got: %s", rule, out)
			}
		}
	})
}

func TestPrintSARIF(t *testing.T) {
	t.Run("with_findings", func(t *testing.T) {
		findings := []Finding{
			{Pos: "auth.go:10:5", Rule: "CT001", Message: "CT001: branch depends on secret"},
			{Pos: "crypto.go:20", Rule: "CT002", Message: "CT002: comparison"},
		}
		out := captureStdout(t, func() { printSARIF(findings) })

		var report SarifReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("invalid SARIF JSON: %v", err)
		}
		if report.Version != "2.1.0" {
			t.Errorf("expected SARIF version 2.1.0, got %s", report.Version)
		}
		if len(report.Runs) != 1 {
			t.Fatalf("expected 1 run, got %d", len(report.Runs))
		}
		if len(report.Runs[0].Results) != 2 {
			t.Errorf("expected 2 results, got %d", len(report.Runs[0].Results))
		}
		if report.Runs[0].Results[0].RuleID != "CT001" {
			t.Errorf("expected CT001, got %s", report.Runs[0].Results[0].RuleID)
		}
		if len(report.Runs[0].Tool.Driver.Rules) != 7 {
			t.Errorf("expected 7 rule definitions, got %d", len(report.Runs[0].Tool.Driver.Rules))
		}
	})

	t.Run("empty_findings", func(t *testing.T) {
		out := captureStdout(t, func() { printSARIF(nil) })

		var report SarifReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("invalid SARIF JSON: %v", err)
		}
		if len(report.Runs[0].Results) != 0 {
			t.Errorf("expected 0 results, got %d", len(report.Runs[0].Results))
		}
	})

	t.Run("finding_without_pos", func(t *testing.T) {
		findings := []Finding{
			{Rule: "CT001", Message: "CT001: no position"},
		}
		out := captureStdout(t, func() { printSARIF(findings) })

		var report SarifReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("invalid SARIF JSON: %v", err)
		}
		if len(report.Runs[0].Results[0].Locations) != 0 {
			t.Errorf("expected 0 locations for finding without pos")
		}
	})
}

func TestPrintSummary(t *testing.T) {
	// Disable colors for deterministic output
	oldC := c
	c = colors{}
	defer func() { c = oldC }()

	t.Run("no_issues", func(t *testing.T) {
		out := captureStdout(t, func() { printSummary(nil, false) })
		if !strings.Contains(out, "No issues found") {
			t.Errorf("expected 'No issues found', got: %q", out)
		}
	})

	t.Run("with_issues", func(t *testing.T) {
		findings := []Finding{
			{Rule: "CT001"}, {Rule: "CT001"}, {Rule: "CT002"},
		}
		out := captureStdout(t, func() { printSummary(findings, false) })
		if !strings.Contains(out, "3") {
			t.Errorf("expected count 3 in output, got: %q", out)
		}
		if !strings.Contains(out, "CT001=2") {
			t.Errorf("expected CT001=2 in output, got: %q", out)
		}
		if !strings.Contains(out, "CT002=1") {
			t.Errorf("expected CT002=1 in output, got: %q", out)
		}
	})

	t.Run("to_stderr", func(t *testing.T) {
		// When toStderr=true, stdout should be empty
		out := captureStdout(t, func() {
			printSummary([]Finding{{Rule: "CT001"}}, true)
		})
		if out != "" {
			t.Errorf("expected empty stdout when toStderr=true, got: %q", out)
		}
	})

	t.Run("unknown_rule", func(t *testing.T) {
		findings := []Finding{{Rule: ""}}
		out := captureStdout(t, func() { printSummary(findings, false) })
		if !strings.Contains(out, "UNKNOWN=1") {
			t.Errorf("expected UNKNOWN=1, got: %q", out)
		}
	})
}
