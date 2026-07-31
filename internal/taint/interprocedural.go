package taint

import (
	"go/types"

	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/oasilturk/ctguard/internal/annotations"
)

// FunctionContext holds taint information for a function.
//
// Taint is tracked at two granularities that flow across call/return boundaries
// as a monotone fixed point: whole-value (SecretParams / TaintedReturn) and
// field-scoped (SecretParamFields / ReturnFields). A struct carrying a secret
// only in some fields propagates just those field paths, so a sibling public
// field stays clean in the callee or caller.
type FunctionContext struct {
	Function          *ssa.Function
	SecretParams      map[string]bool            // params secret as a whole (annotation or wholly-tainted arg)
	SecretParamFields map[string]map[string]bool // param name -> tainted field paths
	TaintedReturn     bool                       // returns a wholly-tainted value
	ReturnFields      map[string]bool            // tainted field paths of the returned struct
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
			Function:          fn,
			SecretParams:      make(map[string]bool),
			SecretParamFields: make(map[string]map[string]bool),
			ReturnFields:      make(map[string]bool),
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

// updateReturnTaint recalculates a function's return taint at both granularities:
// TaintedReturn for a wholly-tainted return, ReturnFields for a struct return
// tainted only in specific fields. Monotone: fields only accumulate.
func (ia *InterproceduralAnalyzer) updateReturnTaint(ctx *FunctionContext, dep *Depender) bool {
	changed := false
	for _, block := range ctx.Function.Blocks {
		for _, instr := range block.Instrs {
			ret, ok := instr.(*ssa.Return)
			if !ok {
				continue
			}
			for _, result := range ret.Results {
				whole, fields := dep.ArgFieldTaint(result)
				if whole {
					if !ctx.TaintedReturn {
						ctx.TaintedReturn = true
						changed = true
					}
					continue
				}
				for _, f := range fields {
					if !ctx.ReturnFields[f] {
						ctx.ReturnFields[f] = true
						changed = true
					}
				}
			}
		}
	}
	return changed
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
				if i >= len(callee.Params) {
					continue
				}
				whole, fields := dep.ArgFieldTaint(arg)
				if !whole && len(fields) == 0 {
					continue
				}
				paramName := callee.Params[i].Name()
				if whole {
					if !calleeCtx.SecretParams[paramName] {
						calleeCtx.SecretParams[paramName] = true
						changed = true
					}
					continue
				}
				fm := calleeCtx.SecretParamFields[paramName]
				if fm == nil {
					fm = map[string]bool{}
					calleeCtx.SecretParamFields[paramName] = fm
				}
				for _, f := range fields {
					if !fm[f] {
						fm[f] = true
						changed = true
					}
				}
			}
		}
	}
	return changed
}

// SecretParamFields returns the field-scoped secret params for fn (param name ->
// tainted field paths), used to seed field-level taint without whole-param taint.
func (ia *InterproceduralAnalyzer) SecretParamFields(fn *ssa.Function) map[string]map[string]bool {
	if ctx := ia.contexts[fn]; ctx != nil {
		return ctx.SecretParamFields
	}
	return nil
}

// ReturnFields returns the tainted field paths of fn's returned struct, used to
// seed field-level taint on a call result without whole-value taint.
func (ia *InterproceduralAnalyzer) ReturnFields(fn *ssa.Function) map[string]bool {
	if ctx := ia.contexts[fn]; ctx != nil {
		return ctx.ReturnFields
	}
	return nil
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
