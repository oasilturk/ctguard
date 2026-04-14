package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

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
