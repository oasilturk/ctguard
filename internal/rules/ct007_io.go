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

				pos := call.Pos()
				if pos == token.NoPos {
					pos = fn.Pos()
				}
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

	pos := call.Pos()
	if pos == token.NoPos {
		pos = fn.Pos()
	}

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

type ct007SinkKey struct {
	pkg  string
	name string
}

// CT004 sinks (fmt.*, log.*) are intentionally excluded to avoid overlap.
var ct007Sinks = map[ct007SinkKey]confidence.ConfidenceLevel{
	// net package — network I/O
	{pkg: "net", name: "Dial"}:    confidence.ConfidenceHigh,
	{pkg: "net", name: "DialTCP"}: confidence.ConfidenceHigh,
	{pkg: "net", name: "DialUDP"}: confidence.ConfidenceHigh,
	{pkg: "net", name: "Listen"}:  confidence.ConfidenceHigh,

	// net/http package — HTTP I/O
	{pkg: "net/http", name: "Get"}:        confidence.ConfidenceHigh,
	{pkg: "net/http", name: "Post"}:       confidence.ConfidenceHigh,
	{pkg: "net/http", name: "PostForm"}:   confidence.ConfidenceHigh,
	{pkg: "net/http", name: "NewRequest"}: confidence.ConfidenceHigh,

	// os package — file I/O
	{pkg: "os", name: "Create"}:    confidence.ConfidenceHigh,
	{pkg: "os", name: "OpenFile"}:  confidence.ConfidenceHigh,
	{pkg: "os", name: "WriteFile"}: confidence.ConfidenceHigh,

	// io/ioutil package — file I/O (deprecated but still used)
	{pkg: "io/ioutil", name: "WriteFile"}: confidence.ConfidenceHigh,

	// syscall package — low-level I/O
	{pkg: "syscall", name: "Write"}:  confidence.ConfidenceHigh,
	{pkg: "syscall", name: "Sendto"}: confidence.ConfidenceHigh,
	{pkg: "syscall", name: "Send"}:   confidence.ConfidenceHigh,

	// bufio package — buffered I/O
	{pkg: "bufio", name: "NewWriter"}: confidence.ConfidenceHigh,

	// io package — generic I/O helpers
	{pkg: "io", name: "WriteString"}: confidence.ConfidenceHigh,
	{pkg: "io", name: "Copy"}:        confidence.ConfidenceHigh,
	{pkg: "io", name: "CopyBuffer"}:  confidence.ConfidenceHigh,
}

func ct007SinkPolicy(pkgPath, name string) (confidence.ConfidenceLevel, bool) {
	k := ct007SinkKey{pkg: pkgPath, name: name}
	if conf, ok := ct007Sinks[k]; ok {
		return conf, true
	}
	return confidence.ConfidenceLow, false
}
