package rules

import (
	"fmt"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/oasilturk/ctguard/internal/annotations"
	"github.com/oasilturk/ctguard/internal/taint"
)

// CT003 flags array/slice/map indexing where the index comes from secret data.
func RunCT003(pass *analysis.Pass, ssaRes *buildssa.SSA, secrets annotations.Secrets, ipAnalyzer *taint.InterproceduralAnalyzer) FindingList {
	var findings FindingList

	for _, fn := range ssaRes.SrcFuncs {
		if fn == nil || fn.Blocks == nil {
			continue
		}

		secretParams := ipAnalyzer.GetSecretParams(fn)
		dep := taint.NewDepender(fn, secretParams, ipAnalyzer)

		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				// Index (array/slice read)
				if idx, ok := ins.(*ssa.Index); ok {
					secretName, conf := dep.DependsOn(idx.Index)
					if secretName == "" {
						continue
					}

					pos := bestPos(idx.Pos(), idx.Index.Pos(), fn.Pos())

					findings = append(findings, Finding{
						Diagnostic: analysis.Diagnostic{
							Pos:      pos,
							Message:  fmt.Sprintf("CT003: array/slice index depends on secret '%s'", secretName),
							Category: fn.String(),
						},
						Confidence: conf,
					})
					continue
				}

				// IndexAddr (array/slice write)
				if idx, ok := ins.(*ssa.IndexAddr); ok {
					secretName, conf := dep.DependsOn(idx.Index)
					if secretName == "" {
						continue
					}

					pos := bestPos(idx.Pos(), idx.Index.Pos(), fn.Pos())

					findings = append(findings, Finding{
						Diagnostic: analysis.Diagnostic{
							Pos:      pos,
							Message:  fmt.Sprintf("CT003: array/slice index depends on secret '%s'", secretName),
							Category: fn.String(),
						},
						Confidence: conf,
					})
					continue
				}

				// Slice (secret-dependent bounds)
				if sl, ok := ins.(*ssa.Slice); ok {
					// Check Low bound
					if sl.Low != nil {
						if secretName, conf := dep.DependsOn(sl.Low); secretName != "" {
							pos := bestPos(sl.Pos(), sl.Low.Pos(), fn.Pos())
							findings = append(findings, Finding{
								Diagnostic: analysis.Diagnostic{
									Pos:      pos,
									Message:  fmt.Sprintf("CT003: slice lower bound depends on secret '%s'", secretName),
									Category: fn.String(),
								},
								Confidence: conf,
							})
							continue
						}
					}
					// Check High bound
					if sl.High != nil {
						if secretName, conf := dep.DependsOn(sl.High); secretName != "" {
							pos := bestPos(sl.Pos(), sl.High.Pos(), fn.Pos())
							findings = append(findings, Finding{
								Diagnostic: analysis.Diagnostic{
									Pos:      pos,
									Message:  fmt.Sprintf("CT003: slice upper bound depends on secret '%s'", secretName),
									Category: fn.String(),
								},
								Confidence: conf,
							})
							continue
						}
					}
					// Check Max bound
					if sl.Max != nil {
						if secretName, conf := dep.DependsOn(sl.Max); secretName != "" {
							pos := bestPos(sl.Pos(), sl.Max.Pos(), fn.Pos())
							findings = append(findings, Finding{
								Diagnostic: analysis.Diagnostic{
									Pos:      pos,
									Message:  fmt.Sprintf("CT003: slice capacity bound depends on secret '%s'", secretName),
									Category: fn.String(),
								},
								Confidence: conf,
							})
							continue
						}
					}
					continue
				}

				// Lookup (map access)
				if lk, ok := ins.(*ssa.Lookup); ok {
					secretName, conf := dep.DependsOn(lk.Index)
					if secretName == "" {
						continue
					}

					pos := bestPos(lk.Pos(), lk.Index.Pos(), fn.Pos())

					findings = append(findings, Finding{
						Diagnostic: analysis.Diagnostic{
							Pos:      pos,
							Message:  fmt.Sprintf("CT003: map lookup key depends on secret '%s'", secretName),
							Category: fn.String(),
						},
						Confidence: conf,
					})
					continue
				}
			}
		}
	}

	return findings
}
