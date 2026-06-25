package taint

import (
	"go/token"
	"strconv"
	"strings"

	"github.com/oasilturk/ctguard/internal/confidence"
	"golang.org/x/tools/go/ssa"
)

// Depender tracks which SSA values depend on secret parameters.
//
// Content and length taint are tracked separately: len/cap of a secret slice
// propagates only length taint, so an innocent len(secret) read is not reported
// while slice[i] content reads still are.
type Depender struct {
	secretParams       map[string]bool
	memo               map[ssa.Value]string // stores secret name or "" if not tainted
	inStack            map[ssa.Value]bool
	taintedAddrs       map[ssa.Value]string                     // container-level content taint (elements, maps, chans)
	addrLengthTaint    map[ssa.Value]string                     // length taint on memory addresses
	fieldTaint         map[ssa.Value]map[string]string          // field-qualified taint: root -> field path -> secret
	containerHasSecret map[ssa.Value]string                     // whole-value: root holds a secret somewhere
	ipAnalyzer         InterproceduralInfo                      // interprocedural analysis info
	confMemo           map[ssa.Value]confidence.ConfidenceLevel // stores confidence level for each tainted value
	lenMemo            map[ssa.Value]string                     // length-taint secret name, mirrors memo
	lenConfMemo        map[ssa.Value]confidence.ConfidenceLevel // length-taint confidence, mirrors confMemo
}

// InterproceduralInfo provides information about taint across function boundaries
type InterproceduralInfo interface {
	HasTaintedReturn(fn *ssa.Function) bool
	IsAnalyzed(fn *ssa.Function) bool
}

func NewDepender(fn *ssa.Function, secretParams map[string]bool, ipAnalyzer InterproceduralInfo) *Depender {
	d := &Depender{
		secretParams:       secretParams,
		memo:               map[ssa.Value]string{},
		inStack:            map[ssa.Value]bool{},
		taintedAddrs:       map[ssa.Value]string{},
		addrLengthTaint:    map[ssa.Value]string{},
		fieldTaint:         map[ssa.Value]map[string]string{},
		containerHasSecret: map[ssa.Value]string{},
		ipAnalyzer:         ipAnalyzer,
		confMemo:           map[ssa.Value]confidence.ConfidenceLevel{},
		lenMemo:            map[ssa.Value]string{},
		lenConfMemo:        map[ssa.Value]confidence.ConfidenceLevel{},
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

// resolveFieldPath walks an address back to its root value, collecting struct
// field indices into a comma path ("0", "0,1"). The root is whatever the chain
// bottoms out at (Alloc/Parameter/Global/Call/Phi/...); any kind is a valid taint
// key because the same SSA value recurs at the write and read sites. An element
// step (IndexAddr/Index) keeps walking but drops the sub-path below it, so a
// slice-in-struct write like p.coefficients[0] still resolves to root p.
func resolveFieldPath(v ssa.Value) (root ssa.Value, path string, sawIndex bool) {
	var idx []string // root-adjacent first
	for {
		switch a := v.(type) {
		case *ssa.FieldAddr:
			idx = append([]string{strconv.Itoa(a.Field)}, idx...)
			v = a.X
		case *ssa.Field:
			idx = append([]string{strconv.Itoa(a.Field)}, idx...)
			v = a.X
		case *ssa.UnOp:
			if a.Op == token.MUL { // transparent deref
				v = a.X
				continue
			}
			return v, strings.Join(idx, ","), sawIndex
		case *ssa.IndexAddr:
			sawIndex = true
			idx = nil // drop sub-path, keep walking
			v = a.X
		case *ssa.Index:
			sawIndex = true
			idx = nil
			v = a.X
		default:
			return v, strings.Join(idx, ","), sawIndex
		}
	}
}

// indexBaseOf returns the container base (.X of the enclosing IndexAddr) that the
// element-blind reads consult, or addr itself if there is no IndexAddr.
func indexBaseOf(addr ssa.Value) ssa.Value {
	for {
		switch a := addr.(type) {
		case *ssa.IndexAddr:
			return a.X
		case *ssa.FieldAddr:
			addr = a.X
		case *ssa.UnOp:
			if a.Op == token.MUL {
				addr = a.X
				continue
			}
			return addr
		default:
			return addr
		}
	}
}

func (d *Depender) setFieldTaint(root ssa.Value, path, secret string) {
	m := d.fieldTaint[root]
	if m == nil {
		m = map[string]string{}
		d.fieldTaint[root] = m
	}
	m[path] = secret
}

// fieldTainted answers query B (is THIS field secret?). Secret-param roots and
// whole-object stores taint every field; otherwise only an exact or overlapping
// path matches, so siblings do not.
func (d *Depender) fieldTainted(root ssa.Value, path string) (string, bool) {
	if p, ok := root.(*ssa.Parameter); ok && d.secretParams[p.Name()] {
		return p.Name(), true
	}
	if s, ok := d.taintedAddrs[root]; ok { // whole-object store
		return s, true
	}
	for k, s := range d.fieldTaint[root] {
		if k == path || strings.HasPrefix(path, k+",") || strings.HasPrefix(k, path+",") {
			return s, true
		}
	}
	// The root may itself be a wholly-tainted value (e.g. a tainted Call/Phi
	// result, p := taintedCtor()); then every field is tainted. Exclude *ssa.Alloc:
	// DependsOn(Alloc) reflects local sibling-field writes via containerHasSecret,
	// which here would be a false positive.
	if _, isAlloc := root.(*ssa.Alloc); !isAlloc {
		if s, _ := d.DependsOn(root); s != "" {
			return s, true
		}
	}
	return "", false
}

// recordStoreTaint records content taint for a Store: field-qualified for struct
// fields, container-level for element/map/chan/whole-object writes.
func (d *Depender) recordStoreTaint(addr ssa.Value, secret string) {
	root, path, sawIndex := resolveFieldPath(addr)
	d.containerHasSecret[root] = secret // query A: container holds a secret
	switch {
	case sawIndex:
		d.taintedAddrs[indexBaseOf(addr)] = secret // element-blind base
		if path != "" {
			d.setFieldTaint(root, path, secret) // secret in a slice/array-typed field
		}
	case path != "":
		d.setFieldTaint(root, path, secret) // struct-field write
	default:
		d.taintedAddrs[addr] = secret // whole-object store
	}
}

// LengthDependsOn reports the secret iff the length/cap of v depends on it.
// Length taint comes from a secret-sized make()/chan or stored length taint; a
// secret slice's own length is treated as public metadata. Memoized (lenMemo)
// to keep the Phi/Convert traversal linear instead of O(2^k) per path.
//
// Known gap: a secret-length loop bound is not flagged, as it looks like a
// benign len() branch.
func (d *Depender) LengthDependsOn(v ssa.Value) (string, confidence.ConfidenceLevel) {
	if v == nil {
		return "", confidence.ConfidenceLow
	}
	if s, ok := d.lenMemo[v]; ok {
		return s, d.lenConfMemo[v]
	}
	if d.inStack[v] {
		return "", confidence.ConfidenceLow
	}
	d.inStack[v] = true
	defer func() { d.inStack[v] = false }()

	secret, conf := d.computeLengthDependsOn(v)
	d.lenMemo[v] = secret
	d.lenConfMemo[v] = conf
	return secret, conf
}

// computeLengthDependsOn is the structural recursion behind LengthDependsOn;
// call only via LengthDependsOn, which adds the memo and cycle guard.
func (d *Depender) computeLengthDependsOn(v ssa.Value) (string, confidence.ConfidenceLevel) {
	switch t := v.(type) {
	case *ssa.MakeSlice:
		if s, c := d.DependsOn(t.Len); s != "" {
			return s, c
		}
		if t.Cap != nil {
			if s, c := d.DependsOn(t.Cap); s != "" {
				return s, c
			}
		}
		return "", confidence.ConfidenceLow

	case *ssa.MakeChan:
		if t.Size != nil {
			return d.DependsOn(t.Size)
		}
		return "", confidence.ConfidenceLow

	case *ssa.UnOp:
		if t.Op == token.MUL {
			if s, ok := d.addrLengthTaint[t.X]; ok {
				return s, confidence.ConfidenceLow
			}
			return d.LengthDependsOn(t.X)
		}
		return "", confidence.ConfidenceLow

	case *ssa.Phi:
		for _, e := range t.Edges {
			if s, c := d.LengthDependsOn(e); s != "" {
				return s, c
			}
		}
		return "", confidence.ConfidenceLow

	case *ssa.ChangeType:
		return d.LengthDependsOn(t.X)

	case *ssa.Convert:
		return d.LengthDependsOn(t.X)

	case *ssa.Extract:
		return d.LengthDependsOn(t.Tuple)

	case *ssa.Alloc:
		if s, ok := d.addrLengthTaint[t]; ok {
			return s, confidence.ConfidenceLow
		}
		return "", confidence.ConfidenceLow

	case *ssa.FieldAddr:
		if s, ok := d.addrLengthTaint[t]; ok {
			return s, confidence.ConfidenceLow
		}
		return "", confidence.ConfidenceLow

	default:
		return "", confidence.ConfidenceLow
	}
}

// analyzeStores tracks tainted memory locations from Store, MapUpdate, append, and channel Send operations.
func (d *Depender) analyzeStores(fn *ssa.Function) {
	if fn == nil || fn.Blocks == nil {
		return
	}

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			if store, ok := instr.(*ssa.Store); ok {
				if secret, _ := d.DependsOn(store.Val); secret != "" {
					d.recordStoreTaint(store.Addr, secret)
				}
				if lenSecret, _ := d.LengthDependsOn(store.Val); lenSecret != "" {
					d.addrLengthTaint[store.Addr] = lenSecret
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
		} else if builtin, isBuiltin := t.Call.Value.(*ssa.Builtin); isBuiltin {
			switch builtin.Name() {
			case "len", "cap":
				// len/cap expose metadata, not content; only length taint flows.
				for _, a := range t.Call.Args {
					if s, c := d.LengthDependsOn(a); s != "" {
						secret = s
						conf = maxConfidence(conf, c)
					}
				}
			default:
				// append, copy, … are transparent; content taint flows from args.
				for _, a := range t.Call.Args {
					if s, c := d.DependsOn(a); s != "" {
						secret = s
						conf = maxConfidence(conf, c)
					}
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
		case token.MUL: // pointer dereference
			switch ax := t.X.(type) {
			case *ssa.FieldAddr: // *(&r.f): field-qualified (query B)
				root, path, _ := resolveFieldPath(ax)
				if s, ok := d.fieldTainted(root, path); ok {
					secret = s
					conf = confidence.ConfidenceLow
				}
			case *ssa.IndexAddr: // element read: element-blind base, then container oracle
				if s, ok := d.taintedAddrs[ax.X]; ok {
					secret = s
					conf = confidence.ConfidenceLow
				} else if root, _, _ := resolveFieldPath(ax); root != nil {
					if s, ok := d.containerHasSecret[root]; ok {
						secret = s
						conf = confidence.ConfidenceLow
					}
				}
			default: // whole-value deref *p
				if s, ok := d.taintedAddrs[t.X]; ok {
					secret = s
					conf = confidence.ConfidenceLow
				} else if s, ok := d.containerHasSecret[t.X]; ok {
					secret = s
					conf = confidence.ConfidenceLow
				}
			}
			if secret == "" {
				secret, conf = d.DependsOn(t.X) // structural fallback
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
		// query B: this field's taint only (fieldTainted also covers a wholly
		// tainted non-Alloc root), never a sibling's.
		root, path, _ := resolveFieldPath(t)
		if s, ok := d.fieldTainted(root, path); ok {
			secret = s
		}
		conf = confidence.ConfidenceLow

	case *ssa.FieldAddr:
		// query B: this field's taint only, never a sibling's.
		root, path, _ := resolveFieldPath(t)
		if s, ok := d.fieldTainted(root, path); ok {
			secret = s
		}
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
		// query A: tainted if the container holds a secret anywhere
		if s, ok := d.containerHasSecret[t]; ok {
			secret = s
			conf = confidence.ConfidenceLow
		} else if s, ok := d.taintedAddrs[t]; ok {
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
