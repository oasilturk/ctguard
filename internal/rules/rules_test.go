package rules

import (
	"go/token"
	"testing"

	"golang.org/x/tools/go/analysis"

	"github.com/oasilturk/ctguard/internal/confidence"
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

func TestFilterByMinConfidence(t *testing.T) {
	findings := FindingList{
		{Confidence: confidence.ConfidenceHigh, Diagnostic: analysis.Diagnostic{Message: "high finding"}},
		{Confidence: confidence.ConfidenceLow, Diagnostic: analysis.Diagnostic{Message: "low finding"}},
		{Confidence: confidence.ConfidenceHigh, Diagnostic: analysis.Diagnostic{Message: "another high"}},
	}

	t.Run("low_keeps_all", func(t *testing.T) {
		got := findings.FilterByMinConfidence(confidence.ConfidenceLow)
		if len(got) != 3 {
			t.Errorf("expected 3, got %d", len(got))
		}
	})

	t.Run("high_filters_low", func(t *testing.T) {
		got := findings.FilterByMinConfidence(confidence.ConfidenceHigh)
		if len(got) != 2 {
			t.Errorf("expected 2, got %d", len(got))
		}
		for _, f := range got {
			if f.Confidence != confidence.ConfidenceHigh {
				t.Errorf("expected only high confidence, got %v", f.Confidence)
			}
		}
	})

	t.Run("empty_list", func(t *testing.T) {
		got := FindingList(nil).FilterByMinConfidence(confidence.ConfidenceHigh)
		if len(got) != 0 {
			t.Errorf("expected 0, got %d", len(got))
		}
	})
}

func TestBestPos(t *testing.T) {
	t.Run("first valid", func(t *testing.T) {
		got := bestPos(token.Pos(10), token.Pos(20))
		if got != token.Pos(10) {
			t.Errorf("expected 10, got %d", got)
		}
	})

	t.Run("skip no pos", func(t *testing.T) {
		got := bestPos(token.NoPos, token.Pos(20))
		if got != token.Pos(20) {
			t.Errorf("expected 20, got %d", got)
		}
	})

	t.Run("all no pos", func(t *testing.T) {
		got := bestPos(token.NoPos, token.NoPos)
		if got != token.NoPos {
			t.Errorf("expected NoPos, got %d", got)
		}
	})

	t.Run("empty", func(t *testing.T) {
		got := bestPos()
		if got != token.NoPos {
			t.Errorf("expected NoPos, got %d", got)
		}
	})
}

func TestCT007SinkPolicy(t *testing.T) {
	tests := []struct {
		name     string
		pkgPath  string
		funcName string
		want     bool
	}{
		{"net.Dial is sink", "net", "Dial", true},
		{"net.DialTCP is sink", "net", "DialTCP", true},
		{"net/http.Post is sink", "net/http", "Post", true},
		{"os.WriteFile is sink", "os", "WriteFile", true},
		{"syscall.Write is sink", "syscall", "Write", true},
		{"io.Copy is sink", "io", "Copy", true},
		{"bufio.NewWriter is sink", "bufio", "NewWriter", true},
		{"fmt.Println is not sink", "fmt", "Println", false},
		{"empty is not sink", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, got := ct007SinkPolicy(tc.pkgPath, tc.funcName)
			if got != tc.want {
				t.Errorf("ct007SinkPolicy(%q, %q) = %v, want %v", tc.pkgPath, tc.funcName, got, tc.want)
			}
		})
	}
}
