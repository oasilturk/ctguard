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

// channelSecretParam checks if a channel value is a secret parameter.
func channelSecretParam(ch ssa.Value, secretParams map[string]bool) (string, confidence.ConfidenceLevel, bool) {
	if p, ok := ch.(*ssa.Parameter); ok && secretParams[p.Name()] {
		return p.Name(), confidence.ConfidenceHigh, true
	}
	return "", confidence.ConfidenceLow, false
}

// CT006 flags secrets that are sent to or received from channels.
func RunCT006(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets, ipAnalyzer *taint.InterproceduralAnalyzer) FindingList {
	var findings FindingList

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
					secretName, conf := dep.DependsOn(send.X)
					if secretName == "" {
						secretName, conf, _ = channelSecretParam(send.Chan, secretParams)
					}
					if secretName == "" {
						continue
					}

					pos := bestPos(send.Pos(), send.X.Pos(), fn.Pos())

					findings = append(findings, Finding{
						Diagnostic: analysis.Diagnostic{
							Pos: pos,
							Message: fmt.Sprintf(
								"CT006: secret '%s' sent to channel",
								secretName,
							),
							Category: fn.String(),
						},
						Confidence: conf,
					})
					continue
				}

				// Case 2: Channel receive operations (<- ch)
				// channel receive is: ssa.UnOp with Op = token.ARROW
				if unop, ok := ins.(*ssa.UnOp); ok && unop.Op == token.ARROW {
					secretName, conf := dep.IsTaintedChannel(unop.X)
					if secretName == "" {
						secretName, conf, _ = channelSecretParam(unop.X, secretParams)
					}

					if secretName == "" {
						continue
					}

					pos := bestPos(unop.Pos(), unop.X.Pos(), fn.Pos())

					findings = append(findings, Finding{
						Diagnostic: analysis.Diagnostic{
							Pos: pos,
							Message: fmt.Sprintf(
								"CT006: secret '%s' received from channel",
								secretName,
							),
							Category: fn.String(),
						},
						Confidence: conf,
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
								secretName, conf := dep.DependsOn(st.Send)
								if secretName == "" {
									secretName, conf, _ = channelSecretParam(st.Chan, secretParams)
								}
								if secretName != "" {
									pos := bestPos(st.Pos, fn.Pos())

									findings = append(findings, Finding{
										Diagnostic: analysis.Diagnostic{
											Pos: pos,
											Message: fmt.Sprintf(
												"CT006: secret '%s' sent to channel",
												secretName,
											),
											Category: fn.String(),
										},
										Confidence: conf,
									})
								}
							}
						case types.RecvOnly:
							// Receive case: <- st.Chan
							secretName, conf := dep.IsTaintedChannel(st.Chan)
							if secretName == "" {
								secretName, conf, _ = channelSecretParam(st.Chan, secretParams)
							}
							if secretName != "" {
								pos := bestPos(st.Pos, fn.Pos())

								findings = append(findings, Finding{
									Diagnostic: analysis.Diagnostic{
										Pos: pos,
										Message: fmt.Sprintf(
											"CT006: secret '%s' received from channel",
											secretName,
										),
										Category: fn.String(),
									},
									Confidence: conf,
								})
							}
						}
					}
				}
			}
		}
	}

	return findings
}
