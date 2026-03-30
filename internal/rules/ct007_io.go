package rules

import (
	"fmt"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/oasilturk/ctguard/internal/annotations"
	"github.com/oasilturk/ctguard/internal/confidence"
	"github.com/oasilturk/ctguard/internal/taint"
)

// CT007 flags tainted values flowing into I/O sinks within isolated regions.
// CT007 intentionally does NOT overlap with CT004 (log/print sinks).
func RunCT007(
	pass *analysis.Pass,
	ssaRes *buildssa.SSA,
	secrets annotations.Secrets,
	ipAnalyzer *taint.InterproceduralAnalyzer,
	isolated annotations.IsolatedRegions,
) FindingList {
	var findings FindingList

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil || fn.Blocks == nil {
			continue
		}

		secretParams := ipAnalyzer.GetSecretParams(fn)
		dep := taint.NewDepender(fn, secretParams, ipAnalyzer)

		funcIdentity := fn.String()

		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				call, ok := ins.(*ssa.Call)
				if !ok {
					continue
				}

				callee := call.Call.StaticCallee()
				if callee == nil {
					// dynamic dispatch (interface method call), check for generic Write
					findings = append(findings, ct007CheckDynamicCall(
						pass, fn, call, dep, isolated, funcIdentity,
					)...)
					continue
				}

				pkgPath := ""
				if callee.Pkg != nil && callee.Pkg.Pkg != nil {
					pkgPath = callee.Pkg.Pkg.Path()
				}
				name := callee.Name()

				sinkConf, isSink := ct007SinkPolicy(pkgPath, name)
				if !isSink {
					continue
				}

				pos := bestPos(call.Pos(), fn.Pos())
				if !isolated.IsIsolated(pass.Fset, pos, funcIdentity) {
					continue
				}

				secretName, conf := ct007FindSecretInArgs(call.Call.Args, dep)
				if secretName == "" {
					continue
				}

				// Weakest link: overall confidence is the minimum of
				// taint confidence and sink confidence.
				finalConf := conf
				if sinkConf < conf {
					finalConf = sinkConf
				}

				if pos == token.NoPos {
					for _, a := range call.Call.Args {
						if a != nil && a.Pos() != token.NoPos {
							pos = a.Pos()
							break
						}
					}
				}

				findings = append(findings, Finding{
					Diagnostic: analysis.Diagnostic{
						Pos: pos,
						Message: fmt.Sprintf(
							"CT007: secret '%s' reaches I/O sink in isolated region",
							secretName,
						),
						Category: fn.String(),
					},
					Confidence: finalConf,
				})
			}
		}
	}

	return findings
}

func ct007CheckDynamicCall(
	pass *analysis.Pass,
	fn *ssa.Function,
	call *ssa.Call,
	dep *taint.Depender,
	isolated annotations.IsolatedRegions,
	funcIdentity string,
) FindingList {
	var findings FindingList

	// only check method calls (not plain function calls)
	if call.Call.Method == nil {
		return findings
	}

	method := call.Call.Method
	if method.Name() != "Write" {
		return findings
	}

	sig, ok := method.Type().(*types.Signature)
	if !ok {
		return findings
	}
	params := sig.Params()
	results := sig.Results()
	if params.Len() != 1 || results.Len() != 2 {
		return findings
	}
	slice, ok := params.At(0).Type().(*types.Slice)
	if !ok {
		return findings
	}
	basic, ok := slice.Elem().(*types.Basic)
	if !ok || basic.Kind() != types.Byte {
		return findings
	}

	pos := bestPos(call.Pos(), fn.Pos())

	if !isolated.IsIsolated(pass.Fset, pos, funcIdentity) {
		return findings
	}

	secretName, _ := ct007FindSecretInArgs(call.Call.Args, dep)
	if secretName == "" {
		return findings
	}

	findings = append(findings, Finding{
		Diagnostic: analysis.Diagnostic{
			Pos: pos,
			Message: fmt.Sprintf(
				"CT007: secret '%s' reaches I/O sink in isolated region",
				secretName,
			),
			Category: fn.String(),
		},
		Confidence: confidence.ConfidenceLow, // dynamic dispatch: LOW
	})

	return findings
}

func ct007FindSecretInArgs(args []ssa.Value, dep *taint.Depender) (string, confidence.ConfidenceLevel) {
	for _, a := range args {
		if a == nil {
			continue
		}
		if s, c := dep.DependsOn(a); s != "" {
			return s, c
		}
	}
	return "", confidence.ConfidenceLow
}

// --- CT007 sink policy ---

// CT004 sinks (fmt.*, log.*) are intentionally excluded to avoid overlap.
var ct007Sinks = map[CallKey]confidence.ConfidenceLevel{
	// net package — network I/O
	{Pkg: "net", Name: "Dial"}:    confidence.ConfidenceHigh,
	{Pkg: "net", Name: "DialTCP"}: confidence.ConfidenceHigh,
	{Pkg: "net", Name: "DialUDP"}: confidence.ConfidenceHigh,
	{Pkg: "net", Name: "Listen"}:  confidence.ConfidenceHigh,

	// net/http package — HTTP I/O
	{Pkg: "net/http", Name: "Get"}:        confidence.ConfidenceHigh,
	{Pkg: "net/http", Name: "Post"}:       confidence.ConfidenceHigh,
	{Pkg: "net/http", Name: "PostForm"}:   confidence.ConfidenceHigh,
	{Pkg: "net/http", Name: "NewRequest"}: confidence.ConfidenceHigh,

	// os package — file I/O
	{Pkg: "os", Name: "Create"}:    confidence.ConfidenceHigh,
	{Pkg: "os", Name: "OpenFile"}:  confidence.ConfidenceHigh,
	{Pkg: "os", Name: "WriteFile"}: confidence.ConfidenceHigh,

	// io/ioutil package — file I/O (deprecated but still used)
	{Pkg: "io/ioutil", Name: "WriteFile"}: confidence.ConfidenceHigh,

	// syscall package — low-level I/O
	{Pkg: "syscall", Name: "Write"}:  confidence.ConfidenceHigh,
	{Pkg: "syscall", Name: "Sendto"}: confidence.ConfidenceHigh,
	{Pkg: "syscall", Name: "Send"}:   confidence.ConfidenceHigh,

	// bufio package — buffered I/O
	{Pkg: "bufio", Name: "NewWriter"}: confidence.ConfidenceHigh,

	// io package — generic I/O helpers
	{Pkg: "io", Name: "WriteString"}: confidence.ConfidenceHigh,
	{Pkg: "io", Name: "Copy"}:        confidence.ConfidenceHigh,
	{Pkg: "io", Name: "CopyBuffer"}:  confidence.ConfidenceHigh,
}

func ct007SinkPolicy(pkgPath, name string) (confidence.ConfidenceLevel, bool) {
	k := CallKey{Pkg: pkgPath, Name: name}
	if conf, ok := ct007Sinks[k]; ok {
		return conf, true
	}
	return confidence.ConfidenceLow, false
}
