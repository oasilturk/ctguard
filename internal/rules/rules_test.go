package rules

import (
	"testing"

	"github.com/oasilturk/ctguard/internal/annotations"
)

func TestCT002Policy(t *testing.T) {
	tests := []struct {
		name        string
		pkgPath     string
		funcName    string
		wantAllowed bool
		wantRisky   bool
	}{
		// Allowed (constant-time)
		{
			name:        "crypto/subtle.ConstantTimeCompare is allowed",
			pkgPath:     "crypto/subtle",
			funcName:    "ConstantTimeCompare",
			wantAllowed: true,
			wantRisky:   false,
		},
		// Denied (non-constant-time)
		{
			name:        "bytes.Equal is risky",
			pkgPath:     "bytes",
			funcName:    "Equal",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "bytes.Compare is risky",
			pkgPath:     "bytes",
			funcName:    "Compare",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "strings.Compare is risky",
			pkgPath:     "strings",
			funcName:    "Compare",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "strings.EqualFold is risky",
			pkgPath:     "strings",
			funcName:    "EqualFold",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "reflect.DeepEqual is risky",
			pkgPath:     "reflect",
			funcName:    "DeepEqual",
			wantAllowed: false,
			wantRisky:   true,
		},
		// Unknown (neither allowed nor risky)
		{
			name:        "unknown function is neutral",
			pkgPath:     "fmt",
			funcName:    "Println",
			wantAllowed: false,
			wantRisky:   false,
		},
		{
			name:        "empty pkg and name",
			pkgPath:     "",
			funcName:    "",
			wantAllowed: false,
			wantRisky:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allowed, risky := ct002Policy(tc.pkgPath, tc.funcName)
			if allowed != tc.wantAllowed {
				t.Errorf("ct002Policy(%q, %q) allowed = %v, want %v",
					tc.pkgPath, tc.funcName, allowed, tc.wantAllowed)
			}
			if risky != tc.wantRisky {
				t.Errorf("ct002Policy(%q, %q) risky = %v, want %v",
					tc.pkgPath, tc.funcName, risky, tc.wantRisky)
			}
		})
	}
}

func TestSecretParamSetForFn_NilFunction(t *testing.T) {
	secrets := annotations.Secrets{
		FuncSecretParams: map[string]map[string]bool{
			"pkg.Func": {"key": true},
		},
	}

	result := secretParamSetForFn(nil, secrets)
	if len(result) != 0 {
		t.Errorf("expected empty set for nil function, got %v", result)
	}
}

func TestSecretParamSetForFn_EmptySecrets(t *testing.T) {
	secrets := annotations.Secrets{
		FuncSecretParams: map[string]map[string]bool{},
	}

	result := secretParamSetForFn(nil, secrets)
	if len(result) != 0 {
		t.Errorf("expected empty set for empty secrets, got %v", result)
	}
}

// Note: Full function-level testing with real SSA.Function objects
// is done via analysistest in the analyzer package.
