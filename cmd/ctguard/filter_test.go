package main

import (
	"testing"

	"github.com/oasilturk/ctguard/internal/confidence"
)

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
