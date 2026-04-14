package main

import (
	"testing"
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
