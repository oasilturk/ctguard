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

var ct005VariableTimeOps = map[token.Token]string{
	token.QUO: "division",  // /
	token.REM: "remainder", // %
	token.SHL: "shift",     // <<
	token.SHR: "shift",     // >>
}

type ct005CallKey struct {
	pkg  string
	name string
}

var ct005Allow = map[ct005CallKey]struct{}{
	{pkg: "crypto/subtle", name: "ConstantTimeSelect"}: {},
	{pkg: "crypto/subtle", name: "ConstantTimeCopy"}:   {},
	// Note: Most crypto/subtle functions are for comparison, not arithmetic,
	// but we list them here for being complete
}

var ct005Deny = map[ct005CallKey]struct{}{
	{pkg: "math", name: "Mod"}:       {},
	{pkg: "math", name: "Remainder"}: {},

	{pkg: "math/big", name: "Div"}:    {},
	{pkg: "math/big", name: "Mod"}:    {},
	{pkg: "math/big", name: "DivMod"}: {},
	{pkg: "math/big", name: "Quo"}:    {},
	{pkg: "math/big", name: "Rem"}:    {},
	{pkg: "math/big", name: "QuoRem"}: {},

	{pkg: "math/bits", name: "RotateLeft"}:   {},
	{pkg: "math/bits", name: "RotateLeft8"}:  {},
	{pkg: "math/bits", name: "RotateLeft16"}: {},
	{pkg: "math/bits", name: "RotateLeft32"}: {},
	{pkg: "math/bits", name: "RotateLeft64"}: {},
}

func ct005Policy(pkgPath, name string) (allowed bool, risky bool) {
	k := ct005CallKey{pkg: pkgPath, name: name}
	if _, ok := ct005Allow[k]; ok {
		return true, false
	}
	if _, ok := ct005Deny[k]; ok {
		return false, true
	}
	return false, false
}

// CT005 flags variable-time arithmetic operations on secret-tainted data.
func RunCT005(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets, ipAnalyzer *taint.InterproceduralAnalyzer) []analysis.Diagnostic {
	var diags []analysis.Diagnostic

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

					secretName := dep.DependsOn(bo.X)
					if secretName == "" {
						secretName = dep.DependsOn(bo.Y)
					}
					if secretName == "" {
						continue
					}

					pos := bo.Pos()
					if pos == token.NoPos {
						pos = bo.X.Pos()
					}
					if pos == token.NoPos {
						pos = fn.Pos()
					}

					diags = append(diags, analysis.Diagnostic{
						Pos:      pos,
						Message:  fmt.Sprintf("CT005: %s operates on secret '%s'", opDesc, secretName),
						Category: fn.String(),
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
					argPos := token.NoPos
					for _, a := range c.Call.Args {
						if argPos == token.NoPos {
							argPos = a.Pos()
						}
						if s := dep.DependsOn(a); s != "" {
							secretName = s
							break
						}
					}
					if secretName == "" {
						continue
					}

					pos := c.Pos()
					if pos == token.NoPos {
						pos = argPos
					}
					if pos == token.NoPos {
						pos = fn.Pos()
					}

					diags = append(diags, analysis.Diagnostic{
						Pos: pos,
						Message: fmt.Sprintf(
							"CT005: %s.%s uses secret '%s'",
							pkgPath, name, secretName,
						),
						Category: fn.String(),
					})
					continue
				}
			}
		}
	}

	return diags
}
