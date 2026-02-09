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

// CT001: branches whose condition depends on secret data.
func RunCT001(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets) []analysis.Diagnostic {
	var diags []analysis.Diagnostic

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil || fn.Blocks == nil {
			continue
		}

		secretParams := secretParamSetForFn(fn, secrets)
		dep := taint.NewDepender(secretParams)

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

				secretName := dep.DependsOn(i.Cond)
				if secretName == "" {
					continue
				}

				// Get position for the branch
				// SSA If instructions often don't have source positions,
				// so we use the condition's position as best effort
				pos := i.Pos()
				if pos == token.NoPos {
					pos = i.Cond.Pos()
				}
				if pos == token.NoPos {
					pos = fn.Pos()
				}

				diags = append(diags, analysis.Diagnostic{
					Pos:     pos,
					Message: fmt.Sprintf("CT001: branch depends on secret '%s' in %s", secretName, fn.String()),
				})
			}
		}
	}

	return diags
}

// isNilComparison returns true if the condition is a comparison with nil
// (e.g., "err != nil" or "ptr == nil"). These comparisons don't leak
// secret values, only whether the value is nil or not.
func isNilComparison(cond ssa.Value) bool {
	binop, ok := cond.(*ssa.BinOp)
	if !ok {
		return false
	}

	// Must be == or !=
	if binop.Op != token.EQL && binop.Op != token.NEQ {
		return false
	}

	// Check if either operand is nil
	return isNilValue(binop.X) || isNilValue(binop.Y)
}

// isNilValue returns true if v is a nil constant
func isNilValue(v ssa.Value) bool {
	c, ok := v.(*ssa.Const)
	if !ok {
		return false
	}
	return c.Value == nil
}

func secretParamSetForFn(fn *ssa.Function, secrets annotations.Secrets) map[string]bool {
	set := map[string]bool{}
	if fn == nil || fn.Object() == nil {
		return set
	}

	if tf, ok := fn.Object().(*types.Func); ok && tf != nil {
		if m, ok := secrets.FuncSecretParams[tf.FullName()]; ok {
			for k := range m {
				set[k] = true
			}
			return set
		}
		if m, ok := secrets.FuncSecretParams[tf.String()]; ok {
			for k := range m {
				set[k] = true
			}
			return set
		}
	}

	key := fn.Object().String()
	if m, ok := secrets.FuncSecretParams[key]; ok {
		for k := range m {
			set[k] = true
		}
	}
	return set
}
