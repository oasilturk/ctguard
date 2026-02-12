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

// CT004 flags secrets that end up in logs, prints, or error messages.
func RunCT004(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets, ipAnalyzer *taint.InterproceduralAnalyzer) []analysis.Diagnostic {
	var diags []analysis.Diagnostic

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil || fn.Blocks == nil {
			continue
		}

		secretParams := ipAnalyzer.GetSecretParams(fn)
		dep := taint.NewDepender(secretParams)

		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				call, ok := ins.(*ssa.Call)
				if !ok {
					continue
				}

				callee := call.Call.StaticCallee()
				if callee == nil {
					continue
				}

				pkgPath := ""
				if callee.Pkg != nil && callee.Pkg.Pkg != nil {
					pkgPath = callee.Pkg.Pkg.Path()
				}
				name := callee.Name()

				// Check if this is a risky output function
				if !ct004IsRiskyCall(pkgPath, name) {
					continue
				}

				// Check if any argument depends on secret
				var secretName string
				argPos := token.NoPos
				for _, a := range call.Call.Args {
					if argPos == token.NoPos {
						argPos = a.Pos()
					}
					if s := ct004ArgSecretName(a, dep); s != "" {
						secretName = s
						break
					}
				}

				if secretName == "" {
					continue
				}

				pos := call.Pos()
				if pos == token.NoPos {
					pos = argPos
				}
				if pos == token.NoPos {
					pos = fn.Pos()
				}

				diags = append(diags, analysis.Diagnostic{
					Pos: pos,
					Message: fmt.Sprintf(
						"CT004: secret '%s' passed to %s.%s",
						secretName, pkgPath, name,
					),
					Category: fn.String(),
				})
			}
		}
	}

	return diags
}

// ct004ArgSecretName returns the secret name if the argument depends on a secret, empty string otherwise
func ct004ArgSecretName(arg ssa.Value, dep *taint.Depender) string {
	// Direct check first
	if s := dep.DependsOn(arg); s != "" {
		return s
	}

	// Handle variadic slice arguments
	// For variadic calls like fmt.Println(x, y, z), the args are packed into a slice
	if slice, ok := arg.(*ssa.Slice); ok {
		// Check the underlying array
		if s := ct004ArgSecretName(slice.X, dep); s != "" {
			return s
		}
	}

	// Handle Alloc (array allocation for variadic args)
	if alloc, ok := arg.(*ssa.Alloc); ok {
		// Check all values stored into this allocation
		for _, ref := range *alloc.Referrers() {
			if store, ok := ref.(*ssa.Store); ok {
				if s := dep.DependsOn(store.Val); s != "" {
					return s
				}
			}
			if indexAddr, ok := ref.(*ssa.IndexAddr); ok {
				// Check what gets stored at this index
				for _, ref2 := range *indexAddr.Referrers() {
					if store, ok := ref2.(*ssa.Store); ok {
						if s := dep.DependsOn(store.Val); s != "" {
							return s
						}
					}
				}
			}
		}
	}

	return ""
}

// ct004IsRiskyCall returns true if the function may expose secret data
func ct004IsRiskyCall(pkgPath, name string) bool {
	key := ct004CallKey{pkg: pkgPath, name: name}
	_, risky := ct004RiskyFuncs[key]
	return risky
}

type ct004CallKey struct {
	pkg  string
	name string
}

// Functions that may expose secret data through output
var ct004RiskyFuncs = map[ct004CallKey]struct{}{
	// fmt package - printing
	{pkg: "fmt", name: "Print"}:   {},
	{pkg: "fmt", name: "Printf"}:  {},
	{pkg: "fmt", name: "Println"}: {},

	// fmt package - string formatting (returns string that may be logged)
	{pkg: "fmt", name: "Sprint"}:   {},
	{pkg: "fmt", name: "Sprintf"}:  {},
	{pkg: "fmt", name: "Sprintln"}: {},

	// fmt package - file/writer output
	{pkg: "fmt", name: "Fprint"}:   {},
	{pkg: "fmt", name: "Fprintf"}:  {},
	{pkg: "fmt", name: "Fprintln"}: {},

	// fmt package - error creation
	{pkg: "fmt", name: "Errorf"}: {},

	// log package - standard logging
	{pkg: "log", name: "Print"}:   {},
	{pkg: "log", name: "Printf"}:  {},
	{pkg: "log", name: "Println"}: {},

	// log package - fatal (logs then exits)
	{pkg: "log", name: "Fatal"}:   {},
	{pkg: "log", name: "Fatalf"}:  {},
	{pkg: "log", name: "Fatalln"}: {},

	// log package - panic (logs then panics)
	{pkg: "log", name: "Panic"}:   {},
	{pkg: "log", name: "Panicf"}:  {},
	{pkg: "log", name: "Panicln"}: {},
}
