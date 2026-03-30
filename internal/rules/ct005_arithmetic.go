package rules

import (
	"fmt"
	"go/token"

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

var ct005Deny = map[CallKey]struct{}{
	{Pkg: "math", Name: "Mod"}:       {},
	{Pkg: "math", Name: "Remainder"}: {},

	{Pkg: "math/big", Name: "Div"}:    {},
	{Pkg: "math/big", Name: "Mod"}:    {},
	{Pkg: "math/big", Name: "DivMod"}: {},
	{Pkg: "math/big", Name: "Quo"}:    {},
	{Pkg: "math/big", Name: "Rem"}:    {},
	{Pkg: "math/big", Name: "QuoRem"}: {},

	{Pkg: "math/bits", Name: "RotateLeft"}:   {},
	{Pkg: "math/bits", Name: "RotateLeft8"}:  {},
	{Pkg: "math/bits", Name: "RotateLeft16"}: {},
	{Pkg: "math/bits", Name: "RotateLeft32"}: {},
	{Pkg: "math/bits", Name: "RotateLeft64"}: {},
}

func ct005Policy(pkgPath, name string) (allowed bool, risky bool) {
	k := CallKey{Pkg: pkgPath, Name: name}
	if _, ok := ct005Allow[k]; ok {
		return true, false
	}
	if _, ok := ct005Deny[k]; ok {
		return false, true
	}
	return false, false
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

					secretName, conf := dep.DependsOn(bo.X)
					if secretName == "" {
						secretName, conf = dep.DependsOn(bo.Y)
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
					callee := c.Call.StaticCallee()
					if callee == nil {
						continue
					}

					pkgPath := ""
					if callee.Pkg != nil && callee.Pkg.Pkg != nil {
						pkgPath = callee.Pkg.Pkg.Path()
					}
					name := callee.Name()

					allowed, risky := ct005Policy(pkgPath, name)
					if allowed {
						continue
					}
					if !risky {
						continue
					}

					var secretName string
					var conf confidence.ConfidenceLevel
					argPos := token.NoPos
					for _, a := range c.Call.Args {
						if argPos == token.NoPos {
							argPos = a.Pos()
						}
						s, c := dep.DependsOn(a)
						if s != "" {
							secretName = s
							conf = c
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
