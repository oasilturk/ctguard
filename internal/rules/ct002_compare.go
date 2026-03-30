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

// CT002: non-constant-time comparisons involving secret-tainted data.
func RunCT002(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets, ipAnalyzer *taint.InterproceduralAnalyzer) FindingList {
	var findings FindingList

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil || fn.Blocks == nil {
			continue
		}

		secretParams := ipAnalyzer.GetSecretParams(fn)
		dep := taint.NewDepender(fn, secretParams, ipAnalyzer)

		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {

				// Case 1: calls like bytes.Equal(...) etc.
				if c, ok := ins.(*ssa.Call); ok {
					callee := c.Call.StaticCallee()
					if callee == nil {
						continue
					}

					pkgPath := ""
					if callee.Pkg != nil && callee.Pkg.Pkg != nil {
						pkgPath = callee.Pkg.Pkg.Path()
					}
					name := callee.Name()

					allowed, risky := ct002Policy(pkgPath, name)
					if allowed {
						continue
					}
					if !risky {
						continue
					}

					var secretName string
					var conf confidence.ConfidenceLevel
					argPos := token.NoPos
					for _, a := range c.Call.Args {
						if argPos == token.NoPos {
							argPos = a.Pos()
						}
						s, c := dep.DependsOn(a)
						if s != "" {
							secretName = s
							conf = c
							break
						}
					}
					if secretName == "" {
						continue
					}

					pos := c.Pos()
					if pos == token.NoPos {
						pos = argPos
					}
					if pos == token.NoPos {
						pos = fn.Pos()
					}

					findings = append(findings, Finding{
						Diagnostic: analysis.Diagnostic{
							Pos: pos,
							Message: fmt.Sprintf(
								"CT002: %s.%s uses secret '%s'",
								pkgPath, name, secretName,
							),
							Category: fn.String(),
						},
						Confidence: conf,
					})
					continue
				}

				// Case 2: string == / !=
				if bo, ok := ins.(*ssa.BinOp); ok {
					if bo.Op != token.EQL && bo.Op != token.NEQ {
						continue
					}
					if !isStringValue(bo.X) || !isStringValue(bo.Y) {
						continue
					}
					secretName, conf := dep.DependsOn(bo.X)
					if secretName == "" {
						secretName, conf = dep.DependsOn(bo.Y)
					}
					if secretName == "" {
						continue
					}

					pos := bo.Pos()
					if pos == token.NoPos {
						pos = bo.X.Pos()
					}
					if pos == token.NoPos {
						pos = fn.Pos()
					}

					findings = append(findings, Finding{
						Diagnostic: analysis.Diagnostic{
							Pos:      pos,
							Message:  fmt.Sprintf("CT002: string comparison uses secret '%s'", secretName),
							Category: fn.String(),
						},
						Confidence: conf,
					})
				}
			}
		}
	}

	return findings
}

func isStringValue(v ssa.Value) bool {
	if v == nil || v.Type() == nil {
		return false
	}
	b, ok := v.Type().Underlying().(*types.Basic)
	return ok && b.Kind() == types.String
}

// --- CT002 policy (allow/deny) ---

var ct002Allow = map[CallKey]struct{}{
	// crypto/subtle — all functions are constant-time by design
	{Pkg: "crypto/subtle", Name: "ConstantTimeCompare"}:  {},
	{Pkg: "crypto/subtle", Name: "ConstantTimeSelect"}:   {},
	{Pkg: "crypto/subtle", Name: "ConstantTimeByteEq"}:   {},
	{Pkg: "crypto/subtle", Name: "ConstantTimeEq"}:       {},
	{Pkg: "crypto/subtle", Name: "ConstantTimeLessOrEq"}: {},
	{Pkg: "crypto/subtle", Name: "ConstantTimeCopy"}:     {},
	{Pkg: "crypto/subtle", Name: "XORBytes"}:             {},
	// crypto/hmac — Equal uses crypto/subtle internally
	{Pkg: "crypto/hmac", Name: "Equal"}: {},
}

var ct002Deny = map[CallKey]struct{}{
	// bytes — non-constant-time comparison / search
	{Pkg: "bytes", Name: "Equal"}:        {},
	{Pkg: "bytes", Name: "Compare"}:      {},
	{Pkg: "bytes", Name: "HasPrefix"}:    {},
	{Pkg: "bytes", Name: "HasSuffix"}:    {},
	{Pkg: "bytes", Name: "Contains"}:     {},
	{Pkg: "bytes", Name: "ContainsAny"}:  {},
	{Pkg: "bytes", Name: "ContainsRune"}: {},
	{Pkg: "bytes", Name: "Index"}:        {},
	{Pkg: "bytes", Name: "LastIndex"}:    {},
	// strings — non-constant-time comparison / search
	{Pkg: "strings", Name: "Compare"}:      {},
	{Pkg: "strings", Name: "EqualFold"}:    {},
	{Pkg: "strings", Name: "HasPrefix"}:    {},
	{Pkg: "strings", Name: "HasSuffix"}:    {},
	{Pkg: "strings", Name: "Contains"}:     {},
	{Pkg: "strings", Name: "ContainsAny"}:  {},
	{Pkg: "strings", Name: "ContainsRune"}: {},
	{Pkg: "strings", Name: "Index"}:        {},
	{Pkg: "strings", Name: "LastIndex"}:    {},
	// reflect — deep comparison is non-constant-time
	{Pkg: "reflect", Name: "DeepEqual"}: {},
}

func ct002Policy(pkgPath, name string) (allowed bool, risky bool) {
	k := CallKey{Pkg: pkgPath, Name: name}
	if _, ok := ct002Allow[k]; ok {
		return true, false
	}
	if _, ok := ct002Deny[k]; ok {
		return false, true
	}
	return false, false
}
