package rules

import (
	"fmt"
	"go/token"
	"slices"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/oasilturk/ctguard/internal/annotations"
	"github.com/oasilturk/ctguard/internal/confidence"
	"github.com/oasilturk/ctguard/internal/taint"
)

var ct005VariableTimeOps = map[token.Token]string{
	token.QUO: "division",  // /
	token.REM: "remainder", // %
	token.SHL: "shift",     // <<
	token.SHR: "shift",     // >>
}

var ct005Allow = map[CallKey]struct{}{
	{Pkg: "crypto/subtle", Name: "ConstantTimeSelect"}: {},
	{Pkg: "crypto/subtle", Name: "ConstantTimeCopy"}:   {},
	// Note: Most crypto/subtle functions are for comparison, not arithmetic,
	// but we list them here for being complete
}

// Value lists the arg indices whose secret-dependence is variable-time; nil means any arg.
var ct005Deny = map[CallKey][]int{
	{Pkg: "math", Name: "Mod"}:       nil,
	{Pkg: "math", Name: "Remainder"}: nil,

	{Pkg: "math/big", Name: "Div"}:    nil,
	{Pkg: "math/big", Name: "Mod"}:    nil,
	{Pkg: "math/big", Name: "DivMod"}: nil,
	{Pkg: "math/big", Name: "Quo"}:    nil,
	{Pkg: "math/big", Name: "Rem"}:    nil,
	{Pkg: "math/big", Name: "QuoRem"}: nil,

	{Pkg: "math/bits", Name: "RotateLeft"}:   {1},
	{Pkg: "math/bits", Name: "RotateLeft8"}:  {1},
	{Pkg: "math/bits", Name: "RotateLeft16"}: {1},
	{Pkg: "math/bits", Name: "RotateLeft32"}: {1},
	{Pkg: "math/bits", Name: "RotateLeft64"}: {1},
}

func ct005Policy(pkgPath, name string) (allowed bool, risky bool, riskyArgs []int) {
	k := CallKey{Pkg: pkgPath, Name: name}
	if _, ok := ct005Allow[k]; ok {
		return true, false, nil
	}
	if args, ok := ct005Deny[k]; ok {
		return false, true, args
	}
	return false, false, nil
}

// CT005 flags variable-time arithmetic operations on secret-tainted data.
func RunCT005(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets, ipAnalyzer *taint.InterproceduralAnalyzer) FindingList {
	var findings FindingList

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil || fn.Blocks == nil {
			continue
		}

		secretParams := ipAnalyzer.GetSecretParams(fn)
		dep := taint.NewDepender(fn, secretParams, ipAnalyzer)

		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				if bo, ok := ins.(*ssa.BinOp); ok {
					opDesc, risky := ct005VariableTimeOps[bo.Op]
					if !risky {
						continue
					}

					// Shift timing depends only on the amount, so only a secret-dependent bo.Y is a risk.
					var secretName string
					var conf confidence.ConfidenceLevel
					if bo.Op == token.SHL || bo.Op == token.SHR {
						secretName, conf = dep.DependsOn(bo.Y)
					} else {
						secretName, conf = dep.DependsOn(bo.X)
						if secretName == "" {
							secretName, conf = dep.DependsOn(bo.Y)
						}
					}
					if secretName == "" {
						continue
					}

					pos := bestPos(bo.Pos(), bo.X.Pos(), fn.Pos())

					findings = append(findings, Finding{
						Diagnostic: analysis.Diagnostic{
							Pos:      pos,
							Message:  fmt.Sprintf("CT005: %s operates on secret '%s'", opDesc, secretName),
							Category: fn.String(),
						},
						Confidence: conf,
					})
					continue
				}

				if c, ok := ins.(*ssa.Call); ok {
					pkgPath, name, ok := calleeInfo(c)
					if !ok {
						continue
					}

					allowed, risky, riskyArgs := ct005Policy(pkgPath, name)
					if allowed {
						continue
					}
					if !risky {
						continue
					}

					var secretName string
					var conf confidence.ConfidenceLevel
					argPos := token.NoPos
					for i, a := range c.Call.Args {
						if argPos == token.NoPos {
							argPos = a.Pos()
						}
						if riskyArgs != nil && !slices.Contains(riskyArgs, i) {
							continue
						}
						s, cf := dep.DependsOn(a)
						if s != "" {
							secretName = s
							conf = cf
							break
						}
					}
					if secretName == "" {
						continue
					}

					pos := bestPos(c.Pos(), argPos, fn.Pos())

					findings = append(findings, Finding{
						Diagnostic: analysis.Diagnostic{
							Pos: pos,
							Message: fmt.Sprintf(
								"CT005: %s.%s uses secret '%s'",
								pkgPath, name, secretName,
							),
							Category: fn.String(),
						},
						Confidence: conf,
					})
					continue
				}
			}
		}
	}

	return findings
}
