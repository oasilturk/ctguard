package analyzer

import (
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"

	"github.com/oasilturk/ctguard/internal/annotations"
	"github.com/oasilturk/ctguard/internal/rules"
	"github.com/oasilturk/ctguard/internal/taint"
)

var Analyzer = &analysis.Analyzer{
	Name:     "ctguard",
	Doc:      "Detect potential timing side-channel risks in Go code.",
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	ssaRes := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	secrets := annotations.CollectSecrets(pass)
	ignores := annotations.CollectIgnores(pass)

	ipAnalyzer := taint.NewInterproceduralAnalyzer(ssaRes, secrets)
	ipAnalyzer.Analyze()

	var allDiags []analysis.Diagnostic
	allDiags = append(allDiags, rules.RunCT001(pass, ssaRes, secrets, ipAnalyzer)...)
	allDiags = append(allDiags, rules.RunCT002(pass, ssaRes, secrets, ipAnalyzer)...)
	allDiags = append(allDiags, rules.RunCT003(pass, ssaRes, secrets, ipAnalyzer)...)
	allDiags = append(allDiags, rules.RunCT004(pass, ssaRes, secrets, ipAnalyzer)...)
	allDiags = append(allDiags, rules.RunCT005(pass, ssaRes, secrets, ipAnalyzer)...)

	for _, d := range allDiags {
		ruleID := extractRuleID(d.Message)
		funcName := extractFuncName(d.Category)
		if ignores.ShouldIgnore(pass.Fset, d.Pos, ruleID, funcName) {
			continue
		}
		pass.Report(d)
	}

	return nil, nil
}

// extractRuleID extracts the rule ID from diagnostic message.
// Messages are formatted like: "CT001: ..."
func extractRuleID(msg string) string {
	if idx := strings.Index(msg, ":"); idx > 0 {
		return strings.TrimSpace(msg[:idx])
	}
	return ""
}

// extractFuncName extracts the function name from diagnostic category.
// Category contains full SSA function string like "package.functionName"
func extractFuncName(category string) string {
	if category == "" {
		return ""
	}
	// Get just the function name without package path
	if lastDot := strings.LastIndex(category, "."); lastDot > 0 {
		return category[lastDot+1:]
	}
	return category
}
