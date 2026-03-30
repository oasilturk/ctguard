package rules

import (
	"golang.org/x/tools/go/analysis"

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
