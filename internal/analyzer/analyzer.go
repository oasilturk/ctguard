package analyzer

import (
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"

	"github.com/oasilturk/ctguard/internal/annotations"
	"github.com/oasilturk/ctguard/internal/rules"
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

	// Collect all diagnostics
	var allDiags []analysis.Diagnostic
	allDiags = append(allDiags, rules.RunCT001(pass, ssaRes, secrets)...)
	allDiags = append(allDiags, rules.RunCT002(pass, ssaRes, secrets)...)
	allDiags = append(allDiags, rules.RunCT003(pass, ssaRes, secrets)...)
	allDiags = append(allDiags, rules.RunCT004(pass, ssaRes, secrets)...)

	// Filter and report diagnostics
	for _, d := range allDiags {
		ruleID, funcName := extractDiagInfo(d.Message)
		if ignores.ShouldIgnore(pass.Fset, d.Pos, ruleID, funcName) {
			continue
		}
		pass.Report(d)
	}

	return nil, nil
}

// extractDiagInfo extracts rule ID and function name from a diagnostic message.
// Messages are formatted like: "CT001: ... in package.functionName"
func extractDiagInfo(msg string) (ruleID string, funcName string) {
	// Extract rule ID (first word before colon)
	if idx := strings.Index(msg, ":"); idx > 0 {
		ruleID = strings.TrimSpace(msg[:idx])
	}

	// Extract function name (after " in ")
	if idx := strings.LastIndex(msg, " in "); idx > 0 {
		funcName = strings.TrimSpace(msg[idx+4:])
		// Get just the function name without package path
		if lastDot := strings.LastIndex(funcName, "."); lastDot > 0 {
			funcName = funcName[lastDot+1:]
		}
	}

	return ruleID, funcName
}
