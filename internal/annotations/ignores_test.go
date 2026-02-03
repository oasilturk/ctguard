package annotations

import (
	"testing"
)

func TestParseIgnoreDirective(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantNil   bool
		wantAll   bool
		wantRules []string
	}{
		{
			name:    "not ignore directive",
			input:   "// some comment",
			wantNil: true,
		},
		{
			name:    "ctguard:secret is not ignore",
			input:   "//ctguard:secret key",
			wantNil: true,
		},
		{
			name:    "ignore all rules",
			input:   "//ctguard:ignore",
			wantAll: true,
		},
		{
			name:    "ignore all with spaces",
			input:   "// ctguard:ignore ",
			wantAll: true,
		},
		{
			name:      "ignore single rule",
			input:     "//ctguard:ignore CT001",
			wantRules: []string{"CT001"},
		},
		{
			name:      "ignore multiple rules space separated",
			input:     "//ctguard:ignore CT001 CT002",
			wantRules: []string{"CT001", "CT002"},
		},
		{
			name:      "ignore multiple rules comma separated",
			input:     "//ctguard:ignore CT001,CT002",
			wantRules: []string{"CT001", "CT002"},
		},
		{
			name:      "ignore with reason",
			input:     "//ctguard:ignore CT002 -- using constant-time internally",
			wantRules: []string{"CT002"},
		},
		{
			name:    "ignore all with reason",
			input:   "//ctguard:ignore -- known safe",
			wantAll: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseIgnoreDirective(tt.input)

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected non-nil result")
			}

			if tt.wantAll {
				if len(result) != 0 {
					t.Errorf("expected empty map (ignore all), got %v", result)
				}
				return
			}

			if len(result) != len(tt.wantRules) {
				t.Errorf("expected %d rules, got %d: %v", len(tt.wantRules), len(result), result)
				return
			}

			for _, rule := range tt.wantRules {
				if !result[rule] {
					t.Errorf("expected rule %s in result, got %v", rule, result)
				}
			}
		})
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{123, "123"},
		{9999, "9999"},
	}

	for _, tt := range tests {
		got := itoa(tt.input)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
