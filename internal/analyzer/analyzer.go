package analyzer

import "golang.org/x/tools/go/analysis"

var Analyzer = &analysis.Analyzer{
	Name: "ctguard",
	Doc:  "Detect potential timing side-channel risks in Go code.",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	// TODO: parse annotations, build SSA, run CT001/CT002 rules.
	return nil, nil
}
