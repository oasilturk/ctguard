package rules

import (
	"fmt"
	"go/token"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/oasilturk/ctguard/internal/annotations"
	"github.com/oasilturk/ctguard/internal/confidence"
	"github.com/oasilturk/ctguard/internal/taint"
)

// CT004 flags secrets that end up in logs, prints, or error messages.
func RunCT004(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets, ipAnalyzer *taint.InterproceduralAnalyzer) FindingList {
	var findings FindingList

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil || fn.Blocks == nil {
			continue
		}

		secretParams := ipAnalyzer.GetSecretParams(fn)
		dep := taint.NewDepender(fn, secretParams, ipAnalyzer)

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
				secretName, conf := ct004FindSecretInArgs(call.Call.Args, dep)

				if secretName == "" {
					continue
				}

				pos := call.Pos()
				if pos == token.NoPos {
					for _, a := range call.Call.Args {
						if a != nil {
							pos = a.Pos()
							if pos != token.NoPos {
								break
							}
						}
					}
				}
				if pos == token.NoPos {
					pos = fn.Pos()
				}

				findings = append(findings, Finding{
					Diagnostic: analysis.Diagnostic{
						Pos: pos,
						Message: fmt.Sprintf(
							"CT004: secret '%s' passed to %s.%s",
							secretName, pkgPath, name,
						),
						Category: fn.String(),
					},
					Confidence: conf,
				})
			}
		}
	}

	return findings
}

func ct004FindSecretInArgs(args []ssa.Value, dep *taint.Depender) (string, confidence.ConfidenceLevel) {
	for _, a := range args {
		if a == nil {
			continue
		}
		if secretName, conf := ct004CheckArg(a, dep); secretName != "" {
			return secretName, conf
		}
	}
	return "", confidence.ConfidenceLow
}

func ct004CheckArg(arg ssa.Value, dep *taint.Depender) (string, confidence.ConfidenceLevel) {
	if s, c := dep.DependsOn(arg); s != "" {
		return ct004UpgradeConfidence(s, c, dep)
	}

	// Handle variadic slice arguments
	if slice, ok := arg.(*ssa.Slice); ok {
		if s, c := ct004CheckArg(slice.X, dep); s != "" {
			return s, c
		}
	}

	// Handle Alloc (array allocation for variadic args)
	if alloc, ok := arg.(*ssa.Alloc); ok {
		return ct004CheckAlloc(alloc, dep)
	}

	return "", confidence.ConfidenceLow
}

func ct004CheckAlloc(alloc *ssa.Alloc, dep *taint.Depender) (string, confidence.ConfidenceLevel) {
	refs := alloc.Referrers()
	if refs == nil {
		return "", confidence.ConfidenceLow
	}

	for _, ref := range *refs {
		if store, ok := ref.(*ssa.Store); ok {
			if s, c := ct004CheckArg(store.Val, dep); s != "" {
				return s, c
			}
		}
		if indexAddr, ok := ref.(*ssa.IndexAddr); ok {
			// Check what gets stored at this index
			indexRefs := indexAddr.Referrers()
			if indexRefs == nil {
				continue
			}
			for _, ref2 := range *indexRefs {
				if store, ok := ref2.(*ssa.Store); ok {
					if s, c := ct004CheckArg(store.Val, dep); s != "" {
						return s, c
					}
				}
			}
		}
	}

	return "", confidence.ConfidenceLow
}

func ct004UpgradeConfidence(secretName string, conf confidence.ConfidenceLevel, dep *taint.Depender) (string, confidence.ConfidenceLevel) {
	if dep.IsSecretParam(secretName) {
		return secretName, confidence.ConfidenceHigh
	}
	return secretName, conf
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
