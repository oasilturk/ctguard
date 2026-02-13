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

// CT003 flags array/slice/map indexing where the index comes from secret data.
func RunCT003(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets, ipAnalyzer *taint.InterproceduralAnalyzer) []analysis.Diagnostic {
	var diags []analysis.Diagnostic

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil || fn.Blocks == nil {
			continue
		}

		secretParams := ipAnalyzer.GetSecretParams(fn)
		dep := taint.NewDepender(fn, secretParams)

		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				// Index (array/slice read)
				if idx, ok := ins.(*ssa.Index); ok {
					secretName := dep.DependsOn(idx.Index)
					if secretName == "" {
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
						Pos:      pos,
						Message:  fmt.Sprintf("CT003: array/slice index depends on secret '%s'", secretName),
						Category: fn.String(),
					})
					continue
				}

				// IndexAddr (array/slice write)
				if idx, ok := ins.(*ssa.IndexAddr); ok {
					secretName := dep.DependsOn(idx.Index)
					if secretName == "" {
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
						Pos:      pos,
						Message:  fmt.Sprintf("CT003: array/slice index depends on secret '%s'", secretName),
						Category: fn.String(),
					})
					continue
				}

				// Lookup (map access)
				if lk, ok := ins.(*ssa.Lookup); ok {
					secretName := dep.DependsOn(lk.Index)
					if secretName == "" {
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
						Pos:      pos,
						Message:  fmt.Sprintf("CT003: map lookup key depends on secret '%s'", secretName),
						Category: fn.String(),
					})
					continue
				}
			}
		}
	}

	return diags
}
