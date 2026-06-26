package main

import (
	"strings"
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

// TestParseGoVetFindings is the unit-level regression guard for Bug A: go vet
// -json writes its diagnostics to stdout under Go 1.26+ and to stderr under Go
// 1.25 and earlier. parseGoVetFindings must surface findings from whichever
// stream carries them. (The CLI previously parsed stderr only, dropping every
// finding under Go 1.26.)
func TestParseGoVetFindings(t *testing.T) {
	const onStdout = `{"pkg": {"ctguard": [{"posn": "a.go:1:1", "message": "CT001: x (confidence: high)"}]}}`
	const onStderr = `{"pkg": {"ctguard": [{"posn": "b.go:2:2", "message": "CT002: y (confidence: low)"}]}}`

	t.Run("json_on_stdout_go1.26", func(t *testing.T) {
		got := parseGoVetFindings(onStdout, "")
		if len(got) != 1 {
			t.Fatalf("expected 1 finding from stdout, got %d", len(got))
		}
		if got[0].Rule != "CT001" {
			t.Errorf("expected CT001, got %q", got[0].Rule)
		}
	})

	t.Run("json_on_stderr_go1.25_fallback", func(t *testing.T) {
		got := parseGoVetFindings("", onStderr)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding from stderr fallback, got %d", len(got))
		}
		if got[0].Rule != "CT002" {
			t.Errorf("expected CT002, got %q", got[0].Rule)
		}
	})

	t.Run("stdout_wins_when_both_present", func(t *testing.T) {
		got := parseGoVetFindings(onStdout, onStderr)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding (stdout only), got %d", len(got))
		}
		if got[0].Rule != "CT001" {
			t.Errorf("expected stdout's CT001 to win, got %q", got[0].Rule)
		}
	})

	t.Run("both_empty", func(t *testing.T) {
		if got := parseGoVetFindings("", ""); len(got) != 0 {
			t.Errorf("expected 0 findings, got %d", len(got))
		}
	})

	t.Run("non_json_stderr_noise_ignored", func(t *testing.T) {
		// Real build error text on stderr, no JSON anywhere -> no findings.
		got := parseGoVetFindings("", "# some/pkg\nbuild failed: undefined: Foo\n")
		if len(got) != 0 {
			t.Errorf("expected 0 findings for non-JSON stderr, got %d", len(got))
		}
	})
}

// Regression: a brace in a sibling's compiler error must not drop healthy findings.
func TestParseGoVetFindings_BuildErrorInterleaved(t *testing.T) {
	const stream = "# m/broken\n" +
		"ctguard: broken/broken.go:3:12: expected ')', found '{'\n" +
		"# m/fires\n" +
		"{\n" +
		"\t\"m/fires\": {\n" +
		"\t\t\"ctguard\": [\n" +
		"\t\t\t{\n" +
		"\t\t\t\t\"posn\": \"fires.go:5:14\",\n" +
		"\t\t\t\t\"message\": \"CT001: branch depends on secret 'password' (confidence: high)\"\n" +
		"\t\t\t}\n" +
		"\t\t]\n" +
		"\t}\n" +
		"}\n"

	t.Run("healthy_finding_survives_broken_sibling", func(t *testing.T) {
		got := parseGoVetFindings("", stream)
		if len(got) != 1 {
			t.Fatalf("fail-open: expected the healthy package's finding to survive, got %d findings", len(got))
		}
		if got[0].Rule != "CT001" {
			t.Errorf("expected CT001, got %q", got[0].Rule)
		}
	})

	t.Run("build_error_surfaced", func(t *testing.T) {
		errs := goVetPlainErrors("", stream)
		joined := strings.Join(errs, "\n")
		if !strings.Contains(joined, "expected ')', found '{'") {
			t.Errorf("expected the compiler error to be surfaced, got: %q", joined)
		}
		for _, e := range errs {
			if strings.HasPrefix(strings.TrimSpace(e), "#") {
				t.Errorf("package header leaked into errors: %q", e)
			}
			if strings.Contains(e, "\"message\"") {
				t.Errorf("JSON content leaked into errors: %q", e)
			}
		}
	})
}

// Regression: a brace in the path (inside the "posn" string) must not drop the finding.
func TestParseGoVetFindings_BraceInPath(t *testing.T) {
	const stream = "# m/fires\n" +
		"{\n" +
		"\t\"m/fires\": {\n" +
		"\t\t\"ctguard\": [\n" +
		"\t\t\t{\n" +
		"\t\t\t\t\"posn\": \"/tmp/pa}rent/{x}/fires/f.go:3:33\",\n" +
		"\t\t\t\t\"message\": \"CT001: branch depends on secret 'pw' (confidence: high)\"\n" +
		"\t\t\t}\n" +
		"\t\t]\n" +
		"\t}\n" +
		"}\n"

	got := parseGoVetFindings("", stream)
	if len(got) != 1 {
		t.Fatalf("fail-open: a brace in the path dropped the finding; got %d findings", len(got))
	}
	if got[0].Rule != "CT001" {
		t.Errorf("expected CT001, got %q", got[0].Rule)
	}
	if got[0].Pos != "/tmp/pa}rent/{x}/fires/f.go:3:33" {
		t.Errorf("position mangled: %q", got[0].Pos)
	}
	if goVetParseFailed("", stream) {
		t.Errorf("goVetParseFailed should be false for well-formed JSON with braces in a string")
	}
}

func TestJSONObjectLen(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"simple", `{"a":1}`, 7},
		{"nested", `{"a":{"b":2}}`, 13},
		{"brace_in_string", `{"p":"a}b"}`, 11},
		{"open_brace_in_string", `{"p":"a{b"}`, 11},
		{"escaped_quote_then_brace", `{"p":"a\"}b"}xx`, 13},
		{"unbalanced", `{"a":1`, 0},
		{"trailing_after_object", `{"a":1} trailing`, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := jsonObjectLen(tt.in); got != tt.want {
				t.Errorf("jsonObjectLen(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// Regression: a corrupt JSON object must report a parse failure (fail closed).
func TestGoVetParseFailed_FailClosed(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		if goVetParseFailed("", `{"pkg":{"ctguard":[]}}`) {
			t.Error("valid JSON should not report a parse failure")
		}
	})
	t.Run("corrupt_object", func(t *testing.T) {
		// Balanced braces but not valid JSON (bare word where a value is expected).
		if !goVetParseFailed("", "{not valid json}") {
			t.Error("a balanced-but-invalid JSON block must report a parse failure (fail closed)")
		}
	})
}
