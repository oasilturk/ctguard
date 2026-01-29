package rules

import (
	"fmt"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/oasilturk/ctguard/internal/annotations"
)

// CT001: Secret-dependent branches.
// In Go SSA (x/tools), switch statements are typically lowered into a chain of *ssa.If,
// so checking *ssa.If is enough to catch secret-dependent switch conditions too.
func RunCT001(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets) []analysis.Diagnostic {
	var diags []analysis.Diagnostic

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil || fn.Blocks == nil {
			continue
		}

		secretParams := secretParamSetForFn(fn, secrets)

		memo := map[ssa.Value]bool{}
		inStack := map[ssa.Value]bool{}

		var depends func(ssa.Value) bool
		depends = func(v ssa.Value) bool {
			if v == nil {
				return false
			}
			if val, ok := memo[v]; ok {
				return val
			}
			if inStack[v] {
				// break cycles defensively
				return false
			}
			inStack[v] = true
			defer func() { inStack[v] = false }()

			// Base case: secret parameter
			if p, ok := v.(*ssa.Parameter); ok {
				if secretParams[p.Name()] {
					memo[v] = true
					return true
				}
			}

			switch t := v.(type) {
			case *ssa.UnOp:
				memo[v] = depends(t.X)
				return memo[v]

			case *ssa.BinOp:
				memo[v] = depends(t.X) || depends(t.Y)
				return memo[v]

			case *ssa.Phi:
				for _, e := range t.Edges {
					if depends(e) {
						memo[v] = true
						return true
					}
				}
				memo[v] = false
				return false

			case *ssa.Call:
				for _, a := range t.Call.Args {
					if depends(a) {
						memo[v] = true
						return true
					}
				}
				memo[v] = false
				return false

			case *ssa.ChangeType:
				memo[v] = depends(t.X)
				return memo[v]

			case *ssa.Convert:
				memo[v] = depends(t.X)
				return memo[v]

			case *ssa.MakeInterface:
				memo[v] = depends(t.X)
				return memo[v]

			case *ssa.Extract:
				memo[v] = depends(t.Tuple)
				return memo[v]

			case *ssa.Field:
				memo[v] = depends(t.X)
				return memo[v]

			case *ssa.FieldAddr:
				memo[v] = depends(t.X)
				return memo[v]

			case *ssa.Index:
				memo[v] = depends(t.X) || depends(t.Index)
				return memo[v]

			case *ssa.IndexAddr:
				memo[v] = depends(t.X) || depends(t.Index)
				return memo[v]

			case *ssa.Slice:
				ok := depends(t.X)
				if t.Low != nil {
					ok = ok || depends(t.Low)
				}
				if t.High != nil {
					ok = ok || depends(t.High)
				}
				if t.Max != nil {
					ok = ok || depends(t.Max)
				}
				memo[v] = ok
				return ok

			case *ssa.Lookup:
				memo[v] = depends(t.X) || depends(t.Index)
				return memo[v]

			default:
				memo[v] = false
				return false
			}
		}

		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				i, ok := ins.(*ssa.If)
				if !ok {
					continue
				}

				if !depends(i.Cond) {
					continue
				}

				// SSA instructions sometimes have NoPos. Use the condition position first.
				pos := i.Cond.Pos()
				if pos == token.NoPos {
					pos = i.Pos()
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

	// Try FullName (types.Func), then fallback to String().
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
