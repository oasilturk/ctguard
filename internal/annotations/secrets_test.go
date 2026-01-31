package annotations

import (
	"go/ast"
	"go/token"
	"testing"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single secret",
			input:    "ctguard:secret key",
			expected: []string{"key"},
		},
		{
			name:     "multiple secrets",
			input:    "ctguard:secret key password token",
			expected: []string{"key", "password", "token"},
		},
		{
			name:     "with extra whitespace",
			input:    "  ctguard:secret   key   ",
			expected: []string{"key"},
		},
		{
			name:     "no secrets listed",
			input:    "ctguard:secret",
			expected: nil,
		},
		{
			name:     "not a directive",
			input:    "some other comment",
			expected: nil,
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "plural form also matches (ctguard:secrets)",
			input:    "ctguard:secrets key",
			expected: []string{"key"}, // Note: HasPrefix matches "ctguard:secret*"
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseLine(tc.input)
			if !stringSliceEqual(result, tc.expected) {
				t.Errorf("parseLine(%q) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestParseSecretDirective(t *testing.T) {
	tests := []struct {
		name     string
		comments []*ast.Comment
		expected []string
	}{
		{
			name:     "nil comment group",
			comments: nil,
			expected: nil,
		},
		{
			name: "line comment with secret",
			comments: []*ast.Comment{
				{Text: "//ctguard:secret key"},
			},
			expected: []string{"key"},
		},
		{
			name: "line comment with space",
			comments: []*ast.Comment{
				{Text: "// ctguard:secret key"},
			},
			expected: []string{"key"},
		},
		{
			name: "multiple line comments",
			comments: []*ast.Comment{
				{Text: "// Some doc comment"},
				{Text: "//ctguard:secret key password"},
			},
			expected: []string{"key", "password"},
		},
		{
			name: "block comment",
			comments: []*ast.Comment{
				{Text: "/* ctguard:secret token */"},
			},
			expected: []string{"token"},
		},
		{
			name: "block comment multiline",
			comments: []*ast.Comment{
				{Text: "/*\n * ctguard:secret a\n * ctguard:secret b\n */"},
			},
			expected: []string{"a", "b"},
		},
		{
			name: "no directive",
			comments: []*ast.Comment{
				{Text: "// Just a regular comment"},
			},
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cg *ast.CommentGroup
			if tc.comments != nil {
				cg = &ast.CommentGroup{List: tc.comments}
			}

			result := parseSecretDirective(cg)
			if !stringSliceEqual(result, tc.expected) {
				t.Errorf("parseSecretDirective() = %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestSecretsStruct(t *testing.T) {
	s := Secrets{
		FuncSecretParams: map[string]map[string]bool{
			"pkg.Func": {"key": true, "token": true},
		},
	}

	if _, ok := s.FuncSecretParams["pkg.Func"]; !ok {
		t.Error("expected FuncSecretParams to contain 'pkg.Func'")
	}

	if !s.FuncSecretParams["pkg.Func"]["key"] {
		t.Error("expected 'key' to be secret")
	}

	if !s.FuncSecretParams["pkg.Func"]["token"] {
		t.Error("expected 'token' to be secret")
	}

	if s.FuncSecretParams["pkg.Func"]["other"] {
		t.Error("expected 'other' to not be secret")
	}
}

// stringSliceEqual compares two string slices
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Ensure token package is used (for position testing if needed)
var _ = token.NoPos
