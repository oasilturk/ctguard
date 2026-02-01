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

// CT003: Secret-dependent indexing (table lookups).
// Detects array, slice, and map indexing where the index depends on secret data.
// This can leak information through cache-timing side-channels.
func RunCT003(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets) []analysis.Diagnostic {
	var diags []analysis.Diagnostic

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil || fn.Blocks == nil {
			continue
		}

		secretParams := secretParamSetForFn(fn, secrets)
		dep := taint.NewDepender(secretParams)

		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				// Case 1: Index instruction (array/slice element access) - mostly reading
				if idx, ok := ins.(*ssa.Index); ok {
					if !dep.Depends(idx.Index) {
						continue
					}

					pos := idx.Pos()
					if pos == token.NoPos {
						pos = idx.Index.Pos()
					}
					if pos == token.NoPos {
						pos = fn.Pos()
					}

					diags = append(diags, analysis.Diagnostic{
						Pos:     pos,
						Message: fmt.Sprintf("CT003: secret-dependent array/slice index in %s", fn.String()),
					})
					continue
				}

				// Case 2: IndexAddr instruction (address of array/slice element) - mostly writing
				if idx, ok := ins.(*ssa.IndexAddr); ok {
					if !dep.Depends(idx.Index) {
						continue
					}

					pos := idx.Pos()
					if pos == token.NoPos {
						pos = idx.Index.Pos()
					}
					if pos == token.NoPos {
						pos = fn.Pos()
					}

					diags = append(diags, analysis.Diagnostic{
						Pos:     pos,
						Message: fmt.Sprintf("CT003: secret-dependent array/slice index in %s", fn.String()),
					})
					continue
				}

				// Case 3: Lookup instruction (map access)
				if lk, ok := ins.(*ssa.Lookup); ok {
					if !dep.Depends(lk.Index) {
						continue
					}

					pos := lk.Pos()
					if pos == token.NoPos {
						pos = lk.Index.Pos()
					}
					if pos == token.NoPos {
						pos = fn.Pos()
					}

					diags = append(diags, analysis.Diagnostic{
						Pos:     pos,
						Message: fmt.Sprintf("CT003: secret-dependent map lookup in %s", fn.String()),
					})
					continue
				}
			}
		}
	}

	return diags
}
