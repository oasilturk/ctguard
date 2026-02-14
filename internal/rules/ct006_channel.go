package rules

import (
	"fmt"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/oasilturk/ctguard/internal/annotations"
	"github.com/oasilturk/ctguard/internal/taint"
)

// CT006 flags secrets that are sent to or received from channels.
func RunCT006(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets, ipAnalyzer *taint.InterproceduralAnalyzer) []analysis.Diagnostic {
	var diags []analysis.Diagnostic

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil || fn.Blocks == nil {
			continue
		}

		secretParams := ipAnalyzer.GetSecretParams(fn)
		dep := taint.NewDepender(fn, secretParams, ipAnalyzer)

		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {

				// Case 1: Channel send operations (ch <- value)
				if send, ok := ins.(*ssa.Send); ok {
					secretName := dep.DependsOn(send.X) // send.X is the value being sent
					if secretName == "" {
						// Check if the channel itself is a secret parameter
						if p, ok := send.Chan.(*ssa.Parameter); ok {
							if secretParams[p.Name()] {
								secretName = p.Name()
							}
						}
					}
					if secretName == "" {
						continue
					}

					pos := send.Pos()
					if pos == token.NoPos {
						pos = send.X.Pos()
					}
					if pos == token.NoPos {
						pos = fn.Pos()
					}

					diags = append(diags, analysis.Diagnostic{
						Pos: pos,
						Message: fmt.Sprintf(
							"CT006: secret '%s' sent to channel",
							secretName,
						),
						Category: fn.String(),
					})
					continue
				}

				// Case 2: Channel receive operations (<- ch)
				// channel receive is: ssa.UnOp with Op = token.ARROW
				if unop, ok := ins.(*ssa.UnOp); ok && unop.Op == token.ARROW {
					secretName := dep.IsTaintedChannel(unop.X)

					if secretName == "" {
						if p, ok := unop.X.(*ssa.Parameter); ok {
							if secretParams[p.Name()] {
								secretName = p.Name()
							}
						}
					}

					if secretName == "" {
						continue
					}

					pos := unop.Pos()
					if pos == token.NoPos {
						pos = unop.X.Pos()
					}
					if pos == token.NoPos {
						pos = fn.Pos()
					}

					diags = append(diags, analysis.Diagnostic{
						Pos: pos,
						Message: fmt.Sprintf(
							"CT006: secret '%s' received from channel",
							secretName,
						),
						Category: fn.String(),
					})
					continue
				}

				// Case 3: Select statements
				if sel, ok := ins.(*ssa.Select); ok {
					for _, st := range sel.States {
						switch st.Dir {
						case types.SendOnly:
							// Send case: st.Chan <- st.Send
							if st.Send != nil {
								secretName := dep.DependsOn(st.Send)
								if secretName == "" {
									if p, ok := st.Chan.(*ssa.Parameter); ok {
										if secretParams[p.Name()] {
											secretName = p.Name()
										}
									}
								}
								if secretName != "" {
									pos := st.Pos
									if pos == token.NoPos {
										pos = fn.Pos()
									}

									diags = append(diags, analysis.Diagnostic{
										Pos: pos,
										Message: fmt.Sprintf(
											"CT006: secret '%s' sent to channel",
											secretName,
										),
										Category: fn.String(),
									})
								}
							}
						case types.RecvOnly:
							// Receive case: <- st.Chan
							secretName := dep.IsTaintedChannel(st.Chan)
							if secretName == "" {
								if p, ok := st.Chan.(*ssa.Parameter); ok {
									if secretParams[p.Name()] {
										secretName = p.Name()
									}
								}
							}
							if secretName != "" {
								pos := st.Pos
								if pos == token.NoPos {
									pos = fn.Pos()
								}

								diags = append(diags, analysis.Diagnostic{
									Pos: pos,
									Message: fmt.Sprintf(
										"CT006: secret '%s' received from channel",
										secretName,
									),
									Category: fn.String(),
								})
							}
						}
					}
				}
			}
		}
	}

	return diags
}
