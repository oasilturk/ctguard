package rules

import (
	"fmt"
	"go/token"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/oasilturk/ctguard/internal/annotations"
	"github.com/oasilturk/ctguard/internal/taint"
)

// CT001: branches whose condition depends on secret data.
func RunCT001(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets, ipAnalyzer *taint.InterproceduralAnalyzer) FindingList {
	var findings FindingList

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil || fn.Blocks == nil {
			continue
		}

		secretParams := ipAnalyzer.GetSecretParams(fn)
		dep := taint.NewDepender(fn, secretParams, ipAnalyzer)

		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				i, ok := ins.(*ssa.If)
				if !ok {
					continue
				}

				// Skip nil comparisons (e.g., "if err != nil")
				if isNilComparison(i.Cond) {
					continue
				}

				secretName, conf := dep.DependsOn(i.Cond)
				if secretName == "" {
					continue
				}

				pos := bestPos(i.Pos(), i.Cond.Pos(), fn.Pos())

				findings = append(findings, Finding{
					Diagnostic: analysis.Diagnostic{
						Pos:      pos,
						Message:  fmt.Sprintf("CT001: branch depends on secret '%s'", secretName),
						Category: fn.String(),
					},
					Confidence: conf,
				})
			}
		}
	}

	return findings
}

func isNilComparison(cond ssa.Value) bool {
	binop, ok := cond.(*ssa.BinOp)
	if !ok {
		return false
	}

	if binop.Op != token.EQL && binop.Op != token.NEQ {
		return false
	}

	return isNilValue(binop.X) || isNilValue(binop.Y)
}

func isNilValue(v ssa.Value) bool {
	c, ok := v.(*ssa.Const)
	if !ok {
		return false
	}
	return c.Value == nil
}
