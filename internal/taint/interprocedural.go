package taint

import (
	"go/types"

	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/oasilturk/ctguard/internal/annotations"
)

// FunctionContext holds taint information for a function
type FunctionContext struct {
	Function      *ssa.Function
	SecretParams  map[string]bool
	TaintedReturn bool // whether the function returns a tainted value
}

// InterproceduralAnalyzer propagates taint information across function calls
type InterproceduralAnalyzer struct {
	contexts map[*ssa.Function]*FunctionContext
}

func NewInterproceduralAnalyzer(ssaRes *buildssa.SSA, secrets annotations.Secrets) *InterproceduralAnalyzer {
	ia := &InterproceduralAnalyzer{
		contexts: make(map[*ssa.Function]*FunctionContext),
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
			lookupSecretParams(fn, secrets, ctx.SecretParams)
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

			dep := NewDepender(fn, ctx.SecretParams, ia)

			if ia.updateReturnTaint(ctx, dep) {
				changed = true
			}
			if ia.propagateCallArgs(fn, dep) {
				changed = true
			}
		}

		if !changed {
			break
		}
	}
}

// updateReturnTaint recalculates whether a function returns a tainted value.
func (ia *InterproceduralAnalyzer) updateReturnTaint(ctx *FunctionContext, dep *Depender) bool {
	prev := ctx.TaintedReturn
	ctx.TaintedReturn = ia.hasAnyTaintedReturn(ctx.Function, dep)
	return ctx.TaintedReturn != prev
}

func (ia *InterproceduralAnalyzer) hasAnyTaintedReturn(fn *ssa.Function, dep *Depender) bool {
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			ret, ok := instr.(*ssa.Return)
			if !ok {
				continue
			}
			for _, result := range ret.Results {
				if secret, _ := dep.DependsOn(result); secret != "" {
					return true
				}
			}
		}
	}
	return false
}

// propagateCallArgs propagates taint from caller arguments to callee parameters.
func (ia *InterproceduralAnalyzer) propagateCallArgs(fn *ssa.Function, dep *Depender) bool {
	changed := false
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}

			callee := call.Call.StaticCallee()
			if callee == nil || !ia.isSamePackage(fn, callee) {
				continue
			}

			calleeCtx := ia.contexts[callee]
			if calleeCtx == nil {
				continue
			}

			for i, arg := range call.Call.Args {
				if secret, _ := dep.DependsOn(arg); secret == "" || i >= len(callee.Params) {
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
	return changed
}

func (ia *InterproceduralAnalyzer) GetSecretParams(fn *ssa.Function) map[string]bool {
	if ctx := ia.contexts[fn]; ctx != nil {
		return ctx.SecretParams
	}
	return make(map[string]bool)
}

func (ia *InterproceduralAnalyzer) HasTaintedReturn(fn *ssa.Function) bool {
	if ctx := ia.contexts[fn]; ctx != nil {
		return ctx.TaintedReturn
	}
	return false
}

func (ia *InterproceduralAnalyzer) IsAnalyzed(fn *ssa.Function) bool {
	return ia.contexts[fn] != nil
}

// lookupSecretParams finds secret param annotations for the given function
// by trying progressively less specific keys.
func lookupSecretParams(fn *ssa.Function, secrets annotations.Secrets, dst map[string]bool) {
	var keys []string
	if tf, ok := fn.Object().(*types.Func); ok && tf != nil {
		keys = []string{tf.FullName(), tf.String()}
	} else {
		keys = []string{fn.Object().String()}
	}
	for _, key := range keys {
		if m, ok := secrets.FuncSecretParams[key]; ok {
			for k := range m {
				dst[k] = true
			}
			return
		}
	}
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
