package rules

import (
	"go/token"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"

	"github.com/oasilturk/ctguard/internal/confidence"
)

type Finding struct {
	Diagnostic analysis.Diagnostic
	Confidence confidence.ConfidenceLevel
}

// CallKey identifies a function by package path and name.
// Used by rule policy tables (allow/deny lists).
type CallKey struct {
	Pkg  string
	Name string
}

// bestPos returns the first valid position from the candidates.
func bestPos(candidates ...token.Pos) token.Pos {
	for _, p := range candidates {
		if p != token.NoPos {
			return p
		}
	}
	return token.NoPos
}

// calleeInfo extracts the package path and function name from a static callee.
// Returns false if the call is a dynamic dispatch (no static callee).
func calleeInfo(call *ssa.Call) (pkgPath, name string, ok bool) {
	callee := call.Call.StaticCallee()
	if callee == nil {
		return "", "", false
	}
	if callee.Pkg != nil && callee.Pkg.Pkg != nil {
		pkgPath = callee.Pkg.Pkg.Path()
	}
	return pkgPath, callee.Name(), true
}

type FindingList []Finding

func (fl FindingList) FilterByMinConfidence(minConfidence confidence.ConfidenceLevel) FindingList {
	var filtered FindingList
	for _, f := range fl {
		if f.Confidence.AtLeast(minConfidence) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}
