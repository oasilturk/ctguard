package rules

import (
	"go/token"
	"testing"
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

func TestCT005VariableTimeOps(t *testing.T) {
	tests := []struct {
		name     string
		op       token.Token
		wantName string
		isRisky  bool
	}{
		// Risky operations
		{
			name:     "division is variable-time",
			op:       token.QUO,
			wantName: "division",
			isRisky:  true,
		},
		{
			name:     "remainder is variable-time",
			op:       token.REM,
			wantName: "remainder",
			isRisky:  true,
		},
		{
			name:     "left shift may be variable-time",
			op:       token.SHL,
			wantName: "shift",
			isRisky:  true,
		},
		{
			name:     "right shift may be variable-time",
			op:       token.SHR,
			wantName: "shift",
			isRisky:  true,
		},
		// Safe operations
		{
			name:     "addition is constant-time",
			op:       token.ADD,
			wantName: "",
			isRisky:  false,
		},
		{
			name:     "subtraction is constant-time",
			op:       token.SUB,
			wantName: "",
			isRisky:  false,
		},
		{
			name:     "multiplication is constant-time",
			op:       token.MUL,
			wantName: "",
			isRisky:  false,
		},
		{
			name:     "XOR is constant-time",
			op:       token.XOR,
			wantName: "",
			isRisky:  false,
		},
		{
			name:     "AND is constant-time",
			op:       token.AND,
			wantName: "",
			isRisky:  false,
		},
		{
			name:     "OR is constant-time",
			op:       token.OR,
			wantName: "",
			isRisky:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, isRisky := ct005VariableTimeOps[tc.op]
			if isRisky != tc.isRisky {
				t.Errorf("operation %v: got risky=%v, want %v", tc.op, isRisky, tc.isRisky)
			}
			if name != tc.wantName {
				t.Errorf("operation %v: got name=%q, want %q", tc.op, name, tc.wantName)
			}
		})
	}
}

func TestCT005Policy(t *testing.T) {
	tests := []struct {
		name        string
		pkgPath     string
		funcName    string
		wantAllowed bool
		wantRisky   bool
	}{
		// Allowed (constant-time)
		{
			name:        "crypto/subtle.ConstantTimeSelect is allowed",
			pkgPath:     "crypto/subtle",
			funcName:    "ConstantTimeSelect",
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
		// Denied (variable-time)
		{
			name:        "math.Mod is risky",
			pkgPath:     "math",
			funcName:    "Mod",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "math.Remainder is risky",
			pkgPath:     "math",
			funcName:    "Remainder",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "math/big.Div is risky",
			pkgPath:     "math/big",
			funcName:    "Div",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "math/big.Mod is risky",
			pkgPath:     "math/big",
			funcName:    "Mod",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "math/big.DivMod is risky",
			pkgPath:     "math/big",
			funcName:    "DivMod",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "math/big.Quo is risky",
			pkgPath:     "math/big",
			funcName:    "Quo",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "math/big.Rem is risky",
			pkgPath:     "math/big",
			funcName:    "Rem",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "math/big.QuoRem is risky",
			pkgPath:     "math/big",
			funcName:    "QuoRem",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "math/bits.RotateLeft is risky",
			pkgPath:     "math/bits",
			funcName:    "RotateLeft",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "math/bits.RotateLeft8 is risky",
			pkgPath:     "math/bits",
			funcName:    "RotateLeft8",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "math/bits.RotateLeft16 is risky",
			pkgPath:     "math/bits",
			funcName:    "RotateLeft16",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "math/bits.RotateLeft32 is risky",
			pkgPath:     "math/bits",
			funcName:    "RotateLeft32",
			wantAllowed: false,
			wantRisky:   true,
		},
		{
			name:        "math/bits.RotateLeft64 is risky",
			pkgPath:     "math/bits",
			funcName:    "RotateLeft64",
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
			name:        "math.Sqrt is not flagged",
			pkgPath:     "math",
			funcName:    "Sqrt",
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
			allowed, risky := ct005Policy(tc.pkgPath, tc.funcName)
			if allowed != tc.wantAllowed {
				t.Errorf("ct005Policy(%q, %q) allowed = %v, want %v",
					tc.pkgPath, tc.funcName, allowed, tc.wantAllowed)
			}
			if risky != tc.wantRisky {
				t.Errorf("ct005Policy(%q, %q) risky = %v, want %v",
					tc.pkgPath, tc.funcName, risky, tc.wantRisky)
			}
		})
	}
}

// Note: Full function-level testing with real SSA.Function objects
// is done via analysistest in the analyzer package.
