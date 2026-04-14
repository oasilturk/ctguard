package taint

import (
	"go/token"

	"github.com/oasilturk/ctguard/internal/confidence"
	"golang.org/x/tools/go/ssa"
)

// Depender tracks which SSA values depend on secret parameters.
type Depender struct {
	secretParams map[string]bool
	memo         map[ssa.Value]string // stores secret name or "" if not tainted
	inStack      map[ssa.Value]bool
	taintedAddrs map[ssa.Value]string                     // tracks memory addresses that store tainted values
	ipAnalyzer   InterproceduralInfo                      // interprocedural analysis info
	confMemo     map[ssa.Value]confidence.ConfidenceLevel // stores confidence level for each tainted value
}

// InterproceduralInfo provides information about taint across function boundaries
type InterproceduralInfo interface {
	HasTaintedReturn(fn *ssa.Function) bool
	IsAnalyzed(fn *ssa.Function) bool
}

func NewDepender(fn *ssa.Function, secretParams map[string]bool, ipAnalyzer InterproceduralInfo) *Depender {
	d := &Depender{
		secretParams: secretParams,
		memo:         map[ssa.Value]string{},
		inStack:      map[ssa.Value]bool{},
		taintedAddrs: map[ssa.Value]string{},
		ipAnalyzer:   ipAnalyzer,
		confMemo:     map[ssa.Value]confidence.ConfidenceLevel{},
	}
	d.analyzeStores(fn)
	return d
}

func (d *Depender) IsSecretParam(name string) bool {
	return d.secretParams[name]
}

func maxConfidence(a, b confidence.ConfidenceLevel) confidence.ConfidenceLevel {
	if a.AtLeast(b) {
		return a
	}
	return b
}

// analyzeStores tracks tainted memory locations from Store, MapUpdate, append, and channel Send operations.
func (d *Depender) analyzeStores(fn *ssa.Function) {
	if fn == nil || fn.Blocks == nil {
		return
	}

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			if store, ok := instr.(*ssa.Store); ok {
				secret, _ := d.DependsOn(store.Val)
				if secret == "" {
					continue
				}

				d.taintedAddrs[store.Addr] = secret

				switch addr := store.Addr.(type) {
				case *ssa.IndexAddr:
					d.taintedAddrs[addr.X] = secret
				case *ssa.FieldAddr:
					d.taintedAddrs[addr.X] = secret
				}
				continue
			}

			if mapUpdate, ok := instr.(*ssa.MapUpdate); ok {
				secret, _ := d.DependsOn(mapUpdate.Value)
				if secret == "" {
					continue
				}

				d.taintedAddrs[mapUpdate.Map] = secret
				continue
			}

			// the channel becomes tainted if a secret is sent in
			if send, ok := instr.(*ssa.Send); ok {
				secret, _ := d.DependsOn(send.X)
				if secret == "" {
					continue
				}
				d.taintedAddrs[send.Chan] = secret
				continue
			}

			if call, ok := instr.(*ssa.Call); ok {
				if builtin, ok := call.Call.Value.(*ssa.Builtin); ok && builtin.Name() == "append" {
					for _, arg := range call.Call.Args {
						if secret, _ := d.DependsOn(arg); secret != "" {
							d.taintedAddrs[call] = secret
							break
						}
					}
				}
			}
		}
	}
}

// DependsOn returns the name of the secret this value depends on, or empty string if not tainted.
// The second return value indicates the confidence level of the finding.
func (d *Depender) DependsOn(v ssa.Value) (string, confidence.ConfidenceLevel) {
	if v == nil {
		return "", confidence.ConfidenceLow
	}
	if secret, ok := d.memo[v]; ok {
		if conf, confOk := d.confMemo[v]; confOk {
			return secret, conf
		}
		return secret, confidence.ConfidenceLow
	}
	if d.inStack[v] {
		return "", confidence.ConfidenceLow
	}
	d.inStack[v] = true
	defer func() { d.inStack[v] = false }()

	var secret string
	var conf confidence.ConfidenceLevel

	if p, ok := v.(*ssa.Parameter); ok {
		if d.secretParams[p.Name()] {
			d.memo[v] = p.Name()
			d.confMemo[v] = confidence.ConfidenceHigh
			return p.Name(), confidence.ConfidenceHigh
		}
		d.memo[v] = ""
		d.confMemo[v] = confidence.ConfidenceLow
		return "", confidence.ConfidenceLow
	}

	switch t := v.(type) {
	// binary operations: check both operands, take highest confidence
	case *ssa.BinOp:
		secretX, confX := d.DependsOn(t.X)
		secretY, confY := d.DependsOn(t.Y)
		conf = maxConfidence(confX, confY)
		if secretX != "" {
			secret = secretX
		} else {
			secret = secretY
		}

	// phi nodes: check all edges, take highest confidence
	case *ssa.Phi:
		for _, e := range t.Edges {
			if s, c := d.DependsOn(e); s != "" {
				secret = s
				conf = maxConfidence(conf, c)
			}
		}

	// function calls
	case *ssa.Call:
		callee := t.Call.StaticCallee()
		if callee != nil &&
			d.ipAnalyzer != nil &&
			d.ipAnalyzer.IsAnalyzed(callee) &&
			!d.ipAnalyzer.HasTaintedReturn(callee) {
			// Analyzed same-package callee with no tainted return: definitely not tainted.
			secret = ""
			conf = confidence.ConfidenceLow
		} else if _, isBuiltin := t.Call.Value.(*ssa.Builtin); isBuiltin {
			// Builtins (len, cap, append, copy, …) are language primitives — transparent.
			// Confidence propagates directly from the argument.
			for _, a := range t.Call.Args {
				if s, c := d.DependsOn(a); s != "" {
					secret = s
					conf = maxConfidence(conf, c)
				}
			}
		} else {
			// External or unanalyzed callee: propagate taint from args but cap at LOW
			// confidence because we cannot inspect the function body (prompt item 3).
			for _, a := range t.Call.Args {
				if s, _ := d.DependsOn(a); s != "" {
					secret = s
					break
				}
			}
			conf = confidence.ConfidenceLow
		}

	case *ssa.UnOp:
		switch t.Op {
		case token.MUL: // * as in pointer dereference
			addr := t.X
			if s, ok := d.taintedAddrs[addr]; ok {
				secret = s
				conf = confidence.ConfidenceLow // dereferenced pointer is LOW
			}
			if secret == "" {
				switch addrVal := addr.(type) {
				case *ssa.IndexAddr:
					if s, ok := d.taintedAddrs[addrVal.X]; ok {
						secret = s
						conf = confidence.ConfidenceLow
					}
				case *ssa.FieldAddr:
					if s, ok := d.taintedAddrs[addrVal.X]; ok {
						secret = s
						conf = confidence.ConfidenceLow
					}
				}
			}
			if secret == "" {
				secret, conf = d.DependsOn(addr)
			}
		case token.ARROW: // <- as in channel receive
			// Check if the channel itself is tainted
			if s, ok := d.taintedAddrs[t.X]; ok {
				secret = s
				conf = confidence.ConfidenceLow // channel receive is LOW
			}
			if secret == "" {
				secret, conf = d.DependsOn(t.X)
			}
		default:
			secret, conf = d.DependsOn(t.X)
		}

	case *ssa.ChangeType:
		secret, conf = d.DependsOn(t.X)

	case *ssa.Convert:
		secret, conf = d.DependsOn(t.X)

	case *ssa.MakeInterface:
		secret, conf = d.DependsOn(t.X)

	case *ssa.Extract:
		secret, conf = d.DependsOn(t.Tuple)

	case *ssa.Field:
		if s, ok := d.taintedAddrs[t.X]; ok {
			secret = s
			conf = confidence.ConfidenceLow // field access without field tracking
		}
		if secret == "" {
			secret, conf = d.DependsOn(t.X)
		}

	case *ssa.FieldAddr:
		// no field-level tracking, therefore LOW confidence
		secret, _ = d.DependsOn(t.X)
		conf = confidence.ConfidenceLow

	case *ssa.Index:
		if s, ok := d.taintedAddrs[t.X]; ok {
			secret = s
			conf = confidence.ConfidenceLow // index access without element tracking
		}
		if secret == "" {
			secret, conf = d.DependsOn(t.X)
		}
		if secret == "" {
			secretIndex, confIndex := d.DependsOn(t.Index)
			if secretIndex != "" {
				secret = secretIndex
				conf = maxConfidence(conf, confIndex)
			}
		}

	case *ssa.IndexAddr:
		if s, ok := d.taintedAddrs[t.X]; ok {
			secret = s
			conf = confidence.ConfidenceLow
		}
		if secret == "" {
			secret, conf = d.DependsOn(t.X)
		}
		if secret == "" {
			secretIndex, confIndex := d.DependsOn(t.Index)
			if secretIndex != "" {
				secret = secretIndex
				conf = maxConfidence(conf, confIndex)
			}
		}

	case *ssa.Slice:
		// No element-level tracking, therefore LOW confidence
		secret, _ = d.DependsOn(t.X)
		conf = confidence.ConfidenceLow
		if secret == "" && t.Low != nil {
			secretLow, confLow := d.DependsOn(t.Low)
			if secretLow != "" {
				secret = secretLow
				conf = maxConfidence(conf, confLow)
			}
		}
		if secret == "" && t.High != nil {
			secretHigh, confHigh := d.DependsOn(t.High)
			if secretHigh != "" {
				secret = secretHigh
				conf = maxConfidence(conf, confHigh)
			}
		}
		if secret == "" && t.Max != nil {
			secretMax, confMax := d.DependsOn(t.Max)
			if secretMax != "" {
				secret = secretMax
				conf = maxConfidence(conf, confMax)
			}
		}

	case *ssa.Lookup:
		if s, ok := d.taintedAddrs[t.X]; ok {
			secret = s
			conf = confidence.ConfidenceLow
		}
		if secret == "" {
			secret, conf = d.DependsOn(t.X)
		}
		if secret == "" {
			secretIndex, confIndex := d.DependsOn(t.Index)
			if secretIndex != "" {
				secret = secretIndex
				conf = maxConfidence(conf, confIndex)
			}
		}

	case *ssa.Alloc:
		if s, ok := d.taintedAddrs[t]; ok {
			secret = s
			conf = confidence.ConfidenceLow // tainted allocation is LOW
		}

	case *ssa.Const:
		secret = ""
		conf = confidence.ConfidenceLow

	default:
		// for any other SSA value type, conservatively assume LOW
		conf = confidence.ConfidenceLow
	}

	// if no secret found, default to LOW
	if secret == "" {
		conf = confidence.ConfidenceLow
	}

	d.memo[v] = secret
	d.confMemo[v] = conf
	return secret, conf
}

// IsTaintedChannel returns the secret name if the channel is tainted, empty string otherwise.
// The second return value indicates the confidence level.
func (d *Depender) IsTaintedChannel(ch ssa.Value) (string, confidence.ConfidenceLevel) {
	if s, ok := d.taintedAddrs[ch]; ok {
		return s, confidence.ConfidenceLow
	}
	return "", confidence.ConfidenceLow
}
