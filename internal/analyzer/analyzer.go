package analyzer

import (
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

	for _, d := range rules.RunCT001(pass, ssaRes, secrets) {
		pass.Report(d)
	}

	for _, d := range rules.RunCT002(pass, ssaRes, secrets) {
		pass.Report(d)
	}

	for _, d := range rules.RunCT003(pass, ssaRes, secrets) {
		pass.Report(d)
	}

	for _, d := range rules.RunCT004(pass, ssaRes, secrets) {
		pass.Report(d)
	}

	return nil, nil
}
