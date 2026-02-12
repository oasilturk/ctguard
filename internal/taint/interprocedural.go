package taint

import (
	"go/types"

	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/ssa"

	"github.com/oasilturk/ctguard/internal/annotations"
)

// FunctionContext holds taint information for a function
type FunctionContext struct {
	Function     *ssa.Function
	SecretParams map[string]bool
}

// InterproceduralAnalyzer propagates taint information across function calls
type InterproceduralAnalyzer struct {
	contexts  map[*ssa.Function]*FunctionContext
	callGraph *callgraph.Graph
	pkg       *ssa.Package
}

func NewInterproceduralAnalyzer(ssaRes *buildssa.SSA, secrets annotations.Secrets) *InterproceduralAnalyzer {
	ia := &InterproceduralAnalyzer{
		contexts: make(map[*ssa.Function]*FunctionContext),
	}

	if ssaRes.Pkg != nil {
		ia.pkg = ssaRes.Pkg
		ia.callGraph = cha.CallGraph(ssaRes.Pkg.Prog)
	}

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil {
			continue
		}

		ctx := &FunctionContext{
			Function:     fn,
			SecretParams: make(map[string]bool),
		}

		if fn.Object() != nil {
			if tf, ok := fn.Object().(*types.Func); ok && tf != nil {
				if m, ok := secrets.FuncSecretParams[tf.FullName()]; ok {
					for k := range m {
						ctx.SecretParams[k] = true
					}
				} else if m, ok := secrets.FuncSecretParams[tf.String()]; ok {
					for k := range m {
						ctx.SecretParams[k] = true
					}
				}
			} else {
				key := fn.Object().String()
				if m, ok := secrets.FuncSecretParams[key]; ok {
					for k := range m {
						ctx.SecretParams[k] = true
					}
				}
			}
		}

		ia.contexts[fn] = ctx
	}

	return ia
}

// Analyze performs interprocedural taint propagation using fixed-point iteration
func (ia *InterproceduralAnalyzer) Analyze() {
	maxIterations := 10
	for iteration := 0; iteration < maxIterations; iteration++ {
		changed := false

		for fn, ctx := range ia.contexts {
			if fn.Blocks == nil {
				continue
			}

			dep := NewDepender(ctx.SecretParams)

			for _, block := range fn.Blocks {
				for _, instr := range block.Instrs {
					call, ok := instr.(*ssa.Call)
					if !ok {
						continue
					}

					callee := call.Call.StaticCallee()
					if callee == nil {
						continue
					}

					if !ia.isSamePackage(fn, callee) {
						continue
					}

					calleeCtx := ia.contexts[callee]
					if calleeCtx == nil {
						continue
					}

					for i, arg := range call.Call.Args {
						secretName := dep.DependsOn(arg)
						if secretName == "" {
							continue
						}

						if i >= len(callee.Params) {
							continue
						}

						paramName := callee.Params[i].Name()

						if !calleeCtx.SecretParams[paramName] {
							calleeCtx.SecretParams[paramName] = true
							changed = true
						}
					}
				}
			}
		}

		if !changed {
			break
		}
	}
}

func (ia *InterproceduralAnalyzer) GetSecretParams(fn *ssa.Function) map[string]bool {
	if ctx := ia.contexts[fn]; ctx != nil {
		return ctx.SecretParams
	}
	return make(map[string]bool)
}

func (ia *InterproceduralAnalyzer) isSamePackage(fn1, fn2 *ssa.Function) bool {
	if fn1 == nil || fn2 == nil {
		return false
	}

	pkg1 := fn1.Package()
	pkg2 := fn2.Package()

	if pkg1 == nil || pkg2 == nil {
		return false
	}

	return pkg1.Pkg == pkg2.Pkg
}
