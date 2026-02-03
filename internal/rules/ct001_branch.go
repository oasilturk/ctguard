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

// CT001: Secret-dependent branches.
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
				if !dep.Depends(i.Cond) {
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
					Message: fmt.Sprintf("CT001: secret-dependent branch in %s", fn.String()),
				})
			}
		}
	}

	return diags
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
