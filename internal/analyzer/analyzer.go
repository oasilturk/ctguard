package analyzer

import (
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"

	"github.com/oasilturk/ctguard/internal/annotations"
	"github.com/oasilturk/ctguard/internal/confidence"
	"github.com/oasilturk/ctguard/internal/config"
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

	// Load config for config-based ignores
	cfg, err := config.Load()
	if err != nil {
		cfg = config.Default()
	}

	ipAnalyzer := taint.NewInterproceduralAnalyzer(ssaRes, secrets)
	ipAnalyzer.Analyze()

	var allFindings rules.FindingList
	allFindings = append(allFindings, rules.RunCT001(pass, ssaRes, secrets, ipAnalyzer)...)
	allFindings = append(allFindings, rules.RunCT002(pass, ssaRes, secrets, ipAnalyzer)...)
	allFindings = append(allFindings, rules.RunCT003(pass, ssaRes, secrets, ipAnalyzer)...)
	allFindings = append(allFindings, rules.RunCT004(pass, ssaRes, secrets, ipAnalyzer)...)
	allFindings = append(allFindings, rules.RunCT005(pass, ssaRes, secrets, ipAnalyzer)...)
	allFindings = append(allFindings, rules.RunCT006(pass, ssaRes, secrets, ipAnalyzer)...)

	minConfidence := cfg.GetMinConfidence()
	filteredFindings := allFindings.FilterByMinConfidence(minConfidence)

	for _, f := range filteredFindings {
		d := f.Diagnostic
		ruleID := extractRuleID(d.Message)
		pkgPath, funcName := extractPkgAndFuncName(d.Category)

		// code-based ignores
		if ignores.ShouldIgnore(pass.Fset, d.Pos, ruleID, funcName) {
			continue
		}

		// config-based ignores
		ignoredRules := cfg.GetIgnoredRules(pkgPath, funcName)
		if annotations.ShouldIgnoreFromConfig(ruleID, funcName, ignoredRules) {
			continue
		}

		message := d.Message + " (" + confidence.ConfidenceTag + f.Confidence.String() + ")"
		d.Message = message

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

func extractPkgAndFuncName(category string) (pkgPath, funcName string) {
	if category == "" {
		return "", ""
	}
	lastDot := strings.LastIndex(category, ".")
	if lastDot > 0 {
		funcName = category[lastDot+1:]
		pkgPath = category[:lastDot]
		return pkgPath, funcName
	}
	return "", category
}
