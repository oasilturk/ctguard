package taint

import (
	"go/token"
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

	// Intrinsic return taint: the part of the return taint that does NOT depend on
	// propagated argument taint, i.e. it comes from an in-body source (hmac.New) or
	// an annotated-secret param. It holds at EVERY call site regardless of the
	// arguments. Return taint that is only param-derived (a passthrough that taints
	// its result because a caller happened to pass a secret) is excluded here and
	// must be re-justified by the actual arguments at each call site. Without this
	// split a passthrough summary (e.g. newParser returning its buffer in a field)
	// leaks to unrelated call sites whose arguments are public.
	AnnotatedParams       map[string]bool // params declared secret by annotation (fixed, pre-propagation)
	IntrinsicReturn       bool            // returns a wholly-tainted value independent of arguments
	IntrinsicReturnFields map[string]bool // return field paths tainted independent of arguments

	// Kinds travel with the taint across the boundary so a published
	// authenticator is not reported in the callee it is passed to nor in the
	// caller it is returned to. They only ever rise, keeping the fixed point
	// monotone; an unset kind reads as KindContent.
	ParamKinds          map[string]Kind // param name -> kind of the taint it carries
	ReturnKind          Kind            // kind of the return taint (whole value and fields)
	IntrinsicReturnKind Kind            // kind of the argument-independent return taint
}

// InterproceduralAnalyzer propagates taint information across function calls
type InterproceduralAnalyzer struct {
	contexts map[*ssa.Function]*FunctionContext
	pkg      *ssa.Package       // for scanning synthesized funcs (init) not in SrcFuncs
	macPools map[ssa.Value]bool // sync.Pool values whose New returns a MAC
}

func NewInterproceduralAnalyzer(ssaRes *buildssa.SSA, secrets annotations.Secrets) *InterproceduralAnalyzer {
	ia := &InterproceduralAnalyzer{
		contexts: make(map[*ssa.Function]*FunctionContext),
		pkg:      ssaRes.Pkg,
		macPools: make(map[ssa.Value]bool),
	}

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil {
			continue
		}

		ctx := &FunctionContext{
			Function:              fn,
			SecretParams:          make(map[string]bool),
			SecretParamFields:     make(map[string]map[string]bool),
			ReturnFields:          make(map[string]bool),
			AnnotatedParams:       make(map[string]bool),
			IntrinsicReturnFields: make(map[string]bool),
			ParamKinds:            make(map[string]Kind),
		}

		if fn.Object() != nil {
			lookupSecretParams(fn, secrets, ctx.SecretParams)
		}
		// Snapshot the annotated params before any propagation adds to SecretParams;
		// intrinsic-return analysis treats only these (plus in-body sources) as secret.
		// An annotation declares confidential material, hence content taint.
		for k := range ctx.SecretParams {
			ctx.AnnotatedParams[k] = true
			ctx.ParamKinds[k] = KindContent
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

			// Intrinsic-return facts: re-derive the return taint treating only
			// annotated params (and in-body sources) as secret, and reading only
			// intrinsic taint from callees. This is what holds unconditionally at
			// call sites; the conditional part above is re-checked per call.
			intrDep := NewDepender(fn, ctx.AnnotatedParams, intrinsicView{ia})
			if ia.updateIntrinsicReturn(ctx, intrDep) {
				changed = true
			}
		}

		if !changed {
			break
		}
	}

	// After IntrinsicReturn has stabilized, identify sync.Pool values whose New
	// function returns a MAC, so pool.Get() at a use site is treated as a MAC.
	ia.computeMACPools()
}

// computeMACPools records every sync.Pool value whose New field is set to a
// function that intrinsically returns a MAC (e.g. `sync.Pool{New: func() any {
// return hmac.New(...) }}`). A Get() on such a pool yields MAC state, so a later
// mac.Sum() compared in non-constant time is caught with no annotation. This is a
// principled crypto-source recognition, not a name heuristic.
func (ia *InterproceduralAnalyzer) computeMACPools() {
	// Scan every package function, including the synthesized `init` (where global
	// `var p = sync.Pool{New: ...}` is lowered) which is not in SrcFuncs.
	for _, fn := range ia.allPkgFuncs() {
		if fn.Blocks == nil {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				store, ok := instr.(*ssa.Store)
				if !ok {
					continue
				}
				fa, ok := store.Addr.(*ssa.FieldAddr)
				if !ok || !isSyncPoolNewField(fa) {
					continue
				}
				newFn := funcOfValue(store.Val)
				if newFn != nil && ia.funcIntrinsicallyReturnsMAC(newFn) {
					ia.macPools[poolRootValue(fa.X)] = true
				}
			}
		}
	}
}

// allPkgFuncs returns every function of the package: named members, the
// synthesized init, and their nested anonymous functions.
func (ia *InterproceduralAnalyzer) allPkgFuncs() []*ssa.Function {
	if ia.pkg == nil {
		out := make([]*ssa.Function, 0, len(ia.contexts))
		for fn := range ia.contexts {
			out = append(out, fn)
		}
		return out
	}
	var out []*ssa.Function
	seen := map[*ssa.Function]bool{}
	var add func(fn *ssa.Function)
	add = func(fn *ssa.Function) {
		if fn == nil || seen[fn] {
			return
		}
		seen[fn] = true
		out = append(out, fn)
		for _, a := range fn.AnonFuncs {
			add(a)
		}
	}
	for _, m := range ia.pkg.Members {
		if fn, ok := m.(*ssa.Function); ok {
			add(fn)
		}
	}
	return out
}

// funcIntrinsicallyReturnsMAC reports whether fn returns MAC state regardless of
// arguments. It uses the computed IntrinsicReturn fact when fn was analyzed, and
// otherwise (e.g. an init-scoped anonymous New func) derives it locally.
func (ia *InterproceduralAnalyzer) funcIntrinsicallyReturnsMAC(fn *ssa.Function) bool {
	if ctx := ia.contexts[fn]; ctx != nil {
		return ctx.IntrinsicReturn
	}
	if fn.Blocks == nil {
		return false
	}
	dep := NewDepender(fn, map[string]bool{}, intrinsicView{ia})
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			ret, ok := instr.(*ssa.Return)
			if !ok {
				continue
			}
			for _, r := range ret.Results {
				if whole, _, _ := dep.ArgFieldTaint(r); whole {
					return true
				}
			}
		}
	}
	return false
}

// IsMACPool reports whether v is a sync.Pool whose New returns a MAC.
func (ia *InterproceduralAnalyzer) IsMACPool(v ssa.Value) bool {
	return ia.macPools[poolRootValue(v)]
}

// isSyncPoolNewField reports whether fa addresses the New field of a sync.Pool.
func isSyncPoolNewField(fa *ssa.FieldAddr) bool {
	pt, ok := fa.X.Type().(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := pt.Elem().(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj.Pkg() == nil || obj.Pkg().Path() != "sync" || obj.Name() != "Pool" {
		return false
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || fa.Field < 0 || fa.Field >= st.NumFields() {
		return false
	}
	return st.Field(fa.Field).Name() == "New"
}

// funcOfValue returns the concrete function behind a value stored into a field,
// whether a bare *ssa.Function or a MakeClosure over one.
func funcOfValue(v ssa.Value) *ssa.Function {
	switch t := v.(type) {
	case *ssa.Function:
		return t
	case *ssa.MakeClosure:
		if f, ok := t.Fn.(*ssa.Function); ok {
			return f
		}
	}
	return nil
}

// poolRootValue strips a leading dereference so the pool identity matches between
// the `pool.New = fn` store site and the `pool.Get()` use site.
func poolRootValue(v ssa.Value) ssa.Value {
	if u, ok := v.(*ssa.UnOp); ok && u.Op == token.MUL {
		return u.X
	}
	return v
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
				whole, fields, kind := dep.ArgFieldTaint(result)
				if whole {
					if !ctx.TaintedReturn {
						ctx.TaintedReturn = true
						changed = true
					}
					if k := JoinKind(ctx.ReturnKind, kind); k != ctx.ReturnKind {
						ctx.ReturnKind = k
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
				if len(fields) > 0 {
					if k := JoinKind(ctx.ReturnKind, kind); k != ctx.ReturnKind {
						ctx.ReturnKind = k
						changed = true
					}
				}
			}
		}
	}
	return changed
}

// updateIntrinsicReturn recomputes the argument-independent part of a function's
// return taint (IntrinsicReturn / IntrinsicReturnFields) from a depender seeded
// with only the annotated params and an intrinsic-only view of callees. Monotone.
func (ia *InterproceduralAnalyzer) updateIntrinsicReturn(ctx *FunctionContext, dep *Depender) bool {
	changed := false
	for _, block := range ctx.Function.Blocks {
		for _, instr := range block.Instrs {
			ret, ok := instr.(*ssa.Return)
			if !ok {
				continue
			}
			for _, result := range ret.Results {
				whole, fields, kind := dep.ArgFieldTaint(result)
				if whole {
					if !ctx.IntrinsicReturn {
						ctx.IntrinsicReturn = true
						changed = true
					}
					if k := JoinKind(ctx.IntrinsicReturnKind, kind); k != ctx.IntrinsicReturnKind {
						ctx.IntrinsicReturnKind = k
						changed = true
					}
					continue
				}
				for _, f := range fields {
					if !ctx.IntrinsicReturnFields[f] {
						ctx.IntrinsicReturnFields[f] = true
						changed = true
					}
				}
				if len(fields) > 0 {
					if k := JoinKind(ctx.IntrinsicReturnKind, kind); k != ctx.IntrinsicReturnKind {
						ctx.IntrinsicReturnKind = k
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
				whole, fields, kind := dep.ArgFieldTaint(arg)
				if !whole && len(fields) == 0 {
					continue
				}
				paramName := callee.Params[i].Name()
				if k := JoinKind(calleeCtx.ParamKinds[paramName], kind); k != calleeCtx.ParamKinds[paramName] {
					calleeCtx.ParamKinds[paramName] = k
					changed = true
				}
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

// IntrinsicReturn reports whether fn returns a wholly-tainted value regardless of
// its arguments (in-body source or annotated param), so the call result is secret
// at every call site.
func (ia *InterproceduralAnalyzer) IntrinsicReturn(fn *ssa.Function) bool {
	if ctx := ia.contexts[fn]; ctx != nil {
		return ctx.IntrinsicReturn
	}
	return false
}

// IntrinsicReturnFields returns the return field paths tainted regardless of fn's
// arguments, seeded on a call result unconditionally.
func (ia *InterproceduralAnalyzer) IntrinsicReturnFields(fn *ssa.Function) map[string]bool {
	if ctx := ia.contexts[fn]; ctx != nil {
		return ctx.IntrinsicReturnFields
	}
	return nil
}

// ParamKinds gives the kind of taint each param of fn carries; a param missing
// from the map is read as KindContent by the Depender.
func (ia *InterproceduralAnalyzer) ParamKinds(fn *ssa.Function) map[string]Kind {
	if ctx := ia.contexts[fn]; ctx != nil {
		return ctx.ParamKinds
	}
	return nil
}

// ReturnKind covers both the whole-value and the field-scoped return taint;
// KindContent when fn was not analyzed.
func (ia *InterproceduralAnalyzer) ReturnKind(fn *ssa.Function) Kind {
	if ctx := ia.contexts[fn]; ctx != nil && ctx.ReturnKind != KindNone {
		return ctx.ReturnKind
	}
	return KindContent
}

// IntrinsicReturnKind is ReturnKind for the argument-independent part.
func (ia *InterproceduralAnalyzer) IntrinsicReturnKind(fn *ssa.Function) Kind {
	if ctx := ia.contexts[fn]; ctx != nil && ctx.IntrinsicReturnKind != KindNone {
		return ctx.IntrinsicReturnKind
	}
	return KindContent
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

// intrinsicView presents the analyzer to a Depender so that a callee contributes
// to the caller's return taint only through its INTRINSIC (argument-independent)
// taint: whole-value and field return taint both collapse to the intrinsic facts,
// and propagated param-field taint is hidden. Used to compute a function's own
// intrinsic-return summary without letting conditional taint leak in.
type intrinsicView struct{ ia *InterproceduralAnalyzer }

func (v intrinsicView) HasTaintedReturn(fn *ssa.Function) bool { return v.ia.IntrinsicReturn(fn) }
func (v intrinsicView) IsAnalyzed(fn *ssa.Function) bool       { return v.ia.IsAnalyzed(fn) }
func (v intrinsicView) SecretParamFields(fn *ssa.Function) map[string]map[string]bool {
	return nil
}
func (v intrinsicView) ReturnFields(fn *ssa.Function) map[string]bool {
	return v.ia.IntrinsicReturnFields(fn)
}
func (v intrinsicView) IntrinsicReturn(fn *ssa.Function) bool { return v.ia.IntrinsicReturn(fn) }
func (v intrinsicView) IntrinsicReturnFields(fn *ssa.Function) map[string]bool {
	return v.ia.IntrinsicReturnFields(fn)
}
func (v intrinsicView) IsMACPool(val ssa.Value) bool { return v.ia.IsMACPool(val) }

// The intrinsic pass seeds only annotated params, which are content, so an empty
// map (read as content) is the right answer here.
func (v intrinsicView) ParamKinds(fn *ssa.Function) map[string]Kind { return nil }
func (v intrinsicView) ReturnKind(fn *ssa.Function) Kind            { return v.ia.IntrinsicReturnKind(fn) }
func (v intrinsicView) IntrinsicReturnKind(fn *ssa.Function) Kind {
	return v.ia.IntrinsicReturnKind(fn)
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
