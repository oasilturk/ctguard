package rules

import (
	"fmt"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/oasilturk/ctguard/internal/annotations"
	"github.com/oasilturk/ctguard/internal/taint"
)

// CT002: non-constant-time comparisons involving secret-tainted data.
func RunCT002(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets) []analysis.Diagnostic {
	var diags []analysis.Diagnostic

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil || fn.Blocks == nil {
			continue
		}

		secretParams := secretParamSetForFn(fn, secrets)
		dep := taint.NewDepender(secretParams)

		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {

				// Case 1: calls like bytes.Equal(...) etc.
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

					allowed, risky := ct002Policy(pkgPath, name)
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
							"CT002: %s.%s uses secret '%s'",
							pkgPath, name, secretName,
						),
					})
					continue
				}

				// Case 2: string == / !=
				if bo, ok := ins.(*ssa.BinOp); ok {
					if bo.Op != token.EQL && bo.Op != token.NEQ {
						continue
					}
					if !isStringValue(bo.X) || !isStringValue(bo.Y) {
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
						Pos:     pos,
						Message: fmt.Sprintf("CT002: string comparison uses secret '%s'", secretName),
					})
				}
			}
		}
	}

	return diags
}

func isStringValue(v ssa.Value) bool {
	if v == nil || v.Type() == nil {
		return false
	}
	b, ok := v.Type().Underlying().(*types.Basic)
	return ok && b.Kind() == types.String
}

// --- CT002 policy (allow/deny) ---

type ct002CallKey struct {
	pkg  string
	name string
}

var ct002Allow = map[ct002CallKey]struct{}{
	{pkg: "crypto/subtle", name: "ConstantTimeCompare"}: {},
}

var ct002Deny = map[ct002CallKey]struct{}{
	{pkg: "bytes", name: "Equal"}:       {},
	{pkg: "bytes", name: "Compare"}:     {},
	{pkg: "strings", name: "Compare"}:   {},
	{pkg: "strings", name: "EqualFold"}: {},
	{pkg: "reflect", name: "DeepEqual"}: {},
}

func ct002Policy(pkgPath, name string) (allowed bool, risky bool) {
	k := ct002CallKey{pkg: pkgPath, name: name}
	if _, ok := ct002Allow[k]; ok {
		return true, false
	}
	if _, ok := ct002Deny[k]; ok {
		return false, true
	}
	return false, false
}
