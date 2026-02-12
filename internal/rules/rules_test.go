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
		// --- Allowed (constant-time) ---

		// crypto/subtle
		{
			name:        "crypto/subtle.ConstantTimeCompare is allowed",
			pkgPath:     "crypto/subtle",
			funcName:    "ConstantTimeCompare",
			wantAllowed: true,
			wantRisky:   false,
		},
		{
			name:        "crypto/subtle.ConstantTimeSelect is allowed",
			pkgPath:     "crypto/subtle",
			funcName:    "ConstantTimeSelect",
			wantAllowed: true,
			wantRisky:   false,
		},
		{
			name:        "crypto/subtle.ConstantTimeByteEq is allowed",
			pkgPath:     "crypto/subtle",
			funcName:    "ConstantTimeByteEq",
			wantAllowed: true,
			wantRisky:   false,
		},
		{
			name:        "crypto/subtle.ConstantTimeEq is allowed",
			pkgPath:     "crypto/subtle",
			funcName:    "ConstantTimeEq",
			wantAllowed: true,
			wantRisky:   false,
		},
		{
			name:        "crypto/subtle.ConstantTimeLessOrEq is allowed",
			pkgPath:     "crypto/subtle",
			funcName:    "ConstantTimeLessOrEq",
			wantAllowed: true,
			wantRisky:   false,
		},
		{
			name:        "crypto/subtle.ConstantTimeCopy is allowed",
			pkgPath:     "crypto/subtle",
			funcName:    "ConstantTimeCopy",
			wantAllowed: true,
			wantRisky:   false,
		},
		{
			name:        "crypto/subtle.XORBytes is allowed",
			pkgPath:     "crypto/subtle",
			funcName:    "XORBytes",
			wantAllowed: true,
			wantRisky:   false,
		},
		// crypto/hmac
		{
			name:        "crypto/hmac.Equal is allowed",
			pkgPath:     "crypto/hmac",
			funcName:    "Equal",
			wantAllowed: true,
			wantRisky:   false,
		},

		// --- Denied (non-constant-time) ---

		// bytes
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
			name:        "bytes.HasPrefix is risky",
			pkgPath:     "bytes",
			funcName:    "HasPrefix",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "bytes.HasSuffix is risky",
			pkgPath:     "bytes",
			funcName:    "HasSuffix",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "bytes.Contains is risky",
			pkgPath:     "bytes",
			funcName:    "Contains",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "bytes.ContainsAny is risky",
			pkgPath:     "bytes",
			funcName:    "ContainsAny",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "bytes.ContainsRune is risky",
			pkgPath:     "bytes",
			funcName:    "ContainsRune",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "bytes.Index is risky",
			pkgPath:     "bytes",
			funcName:    "Index",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "bytes.LastIndex is risky",
			pkgPath:     "bytes",
			funcName:    "LastIndex",
			wantAllowed: false,
			wantRisky:   true,
		},
		// strings
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
			name:        "strings.HasPrefix is risky",
			pkgPath:     "strings",
			funcName:    "HasPrefix",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "strings.HasSuffix is risky",
			pkgPath:     "strings",
			funcName:    "HasSuffix",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "strings.Contains is risky",
			pkgPath:     "strings",
			funcName:    "Contains",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "strings.ContainsAny is risky",
			pkgPath:     "strings",
			funcName:    "ContainsAny",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "strings.ContainsRune is risky",
			pkgPath:     "strings",
			funcName:    "ContainsRune",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "strings.Index is risky",
			pkgPath:     "strings",
			funcName:    "Index",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "strings.LastIndex is risky",
			pkgPath:     "strings",
			funcName:    "LastIndex",
			wantAllowed: false,
			wantRisky:   true,
		},
		// reflect
		{
			name:        "reflect.DeepEqual is risky",
			pkgPath:     "reflect",
			funcName:    "DeepEqual",
			wantAllowed: false,
			wantRisky:   true,
		},

		// --- Unknown (neither allowed nor risky) ---
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
