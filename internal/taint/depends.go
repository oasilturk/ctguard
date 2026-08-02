package taint

import (
	"go/token"
	"go/types"
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
	elementTaintRoots  map[ssa.Value]bool                       // roots with a slice/array element write: propagate whole across boundaries
	derivedTaint       map[ssa.Value]string                     // values tainted via an output-parameter transform (hex.Encode(dst, src))
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
	SecretParamFields(fn *ssa.Function) map[string]map[string]bool
	ReturnFields(fn *ssa.Function) map[string]bool
	// IntrinsicReturn(Fields) report the argument-independent part of a callee's
	// return taint, which holds at every call site. Conditional (param-derived)
	// return taint must instead be re-justified by the call's actual arguments.
	IntrinsicReturn(fn *ssa.Function) bool
	IntrinsicReturnFields(fn *ssa.Function) map[string]bool
	// IsMACPool reports whether v is a sync.Pool whose New returns a MAC, so a
	// Get() on it yields MAC state.
	IsMACPool(v ssa.Value) bool
}

func NewDepender(fn *ssa.Function, secretParams map[string]bool, ipAnalyzer InterproceduralInfo) *Depender {
	d := &Depender{
		secretParams:       secretParams,
		memo:               map[ssa.Value]string{},
		inStack:            map[ssa.Value]bool{},
		taintedAddrs:       map[ssa.Value]string{},
		addrLengthTaint:    map[ssa.Value]string{},
		fieldTaint:         map[ssa.Value]map[string]string{},
		elementTaintRoots:  map[ssa.Value]bool{},
		derivedTaint:       map[ssa.Value]string{},
		containerHasSecret: map[ssa.Value]string{},
		ipAnalyzer:         ipAnalyzer,
		confMemo:           map[ssa.Value]confidence.ConfidenceLevel{},
		lenMemo:            map[ssa.Value]string{},
		lenConfMemo:        map[ssa.Value]confidence.ConfidenceLevel{},
	}
	// Seed field-scoped taint from interprocedural facts BEFORE analyzing stores,
	// so a by-value struct param/result spill (`*t0 = r`) can carry field taint
	// into the local it is copied to.
	d.seedParamFieldTaint(fn, ipAnalyzer)
	d.seedCallResultFieldTaint(fn, ipAnalyzer)
	d.analyzeStores(fn)
	d.analyzeOutputParams(fn)
	return d
}

// outParamKey identifies a function that writes a transform of a source slice
// argument into a destination slice argument.
type outParamKey struct{ pkg, name string }

// outParamTransforms maps such functions to the {dst, src} argument indices.
// Indices include a method receiver at arg 0, so base64/base32 methods use 1,2.
var outParamTransforms = map[outParamKey][2]int{
	{"encoding/hex", "Encode"}:    {0, 1},
	{"encoding/hex", "Decode"}:    {0, 1},
	{"encoding/base64", "Encode"}: {1, 2},
	{"encoding/base64", "Decode"}: {1, 2},
	{"encoding/base32", "Encode"}: {1, 2},
	{"encoding/base32", "Decode"}: {1, 2},
}

// analyzeOutputParams propagates taint through functions that write a transform
// of a source argument into a destination slice argument, e.g.
// `hex.Encode(dst, src)`. Without this the encoded MAC loses its taint and a
// later non-constant-time compare of dst is missed (the common allocation-free
// encoding pattern in real crypto code).
func (d *Depender) analyzeOutputParams(fn *ssa.Function) {
	if fn == nil || fn.Blocks == nil {
		return
	}
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			callee := call.Call.StaticCallee()
			if callee == nil || callee.Object() == nil || callee.Object().Pkg() == nil {
				continue
			}
			idx, ok := outParamTransforms[outParamKey{callee.Object().Pkg().Path(), callee.Object().Name()}]
			if !ok {
				continue
			}
			args := call.Call.Args
			if idx[0] >= len(args) || idx[1] >= len(args) {
				continue
			}
			if s, _ := d.DependsOn(args[idx[1]]); s != "" {
				root, _, _ := resolveFieldPath(args[idx[0]])
				d.derivedTaint[root] = s
			}
		}
	}
}

// seedParamFieldTaint marks the specific struct fields of params that carry a
// secret only in those fields (from interprocedural propagation), so a sibling
// public field read stays clean while the secret field is still tainted.
func (d *Depender) seedParamFieldTaint(fn *ssa.Function, ip InterproceduralInfo) {
	if fn == nil || ip == nil {
		return
	}
	spf := ip.SecretParamFields(fn)
	if len(spf) == 0 {
		return
	}
	for _, p := range fn.Params {
		if d.secretParams[p.Name()] {
			continue // wholly secret already: every field is tainted
		}
		for path := range spf[p.Name()] {
			d.setFieldTaint(p, path, p.Name())
		}
	}
}

// seedCallResultFieldTaint marks the tainted fields of a struct returned by an
// analyzed same-package callee, so reading the secret field of the result is
// tainted while sibling public fields stay clean. A callee's INTRINSIC return
// fields (from an in-body source or annotated param) hold at every call site; its
// merely param-derived return fields hold only where a tainted argument actually
// flows into THIS call. Without the latter gate the summary leaks to an unrelated
// public call site (the newParser-in-NewServer cascade); without seeding it at all
// a constructor that takes a MAC and stores it in a field is missed (false negative).
func (d *Depender) seedCallResultFieldTaint(fn *ssa.Function, ip InterproceduralInfo) {
	if fn == nil || ip == nil {
		return
	}
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			callee := call.Call.StaticCallee()
			if callee == nil {
				continue
			}
			for path := range ip.IntrinsicReturnFields(callee) {
				d.setFieldTaint(call, path, callee.Name())
			}
			cond := ip.ReturnFields(callee)
			if len(cond) == 0 || !d.callHasSecretArg(call) {
				continue
			}
			for path := range cond {
				d.setFieldTaint(call, path, callee.Name())
			}
		}
	}
}

// callHasSecretArg reports whether any argument of call is known to carry secret
// content from store-independent facts, used to gate param-derived return-field
// taint at the specific call site.
func (d *Depender) callHasSecretArg(call *ssa.Call) bool {
	for _, a := range call.Call.Args {
		if d.argCarriesSecretPreStore(a, map[ssa.Value]bool{}) {
			return true
		}
	}
	return false
}

// argCarriesSecretPreStore reports whether v carries secret content using only
// facts available before analyzeStores: secret params, already-seeded param-field
// taint, and intrinsic/analyzed call returns. It deliberately avoids DependsOn so
// it neither pollutes the memo nor depends on store analysis; it under-approximates
// taint arriving solely via a local store, which at worst declines to seed a rare
// case rather than leaking.
func (d *Depender) argCarriesSecretPreStore(v ssa.Value, seen map[ssa.Value]bool) bool {
	if v == nil || seen[v] {
		return false
	}
	seen[v] = true
	switch t := v.(type) {
	case *ssa.Parameter:
		return d.secretParams[t.Name()]
	case *ssa.ChangeType:
		return d.argCarriesSecretPreStore(t.X, seen)
	case *ssa.Convert:
		return d.argCarriesSecretPreStore(t.X, seen)
	case *ssa.MakeInterface:
		return d.argCarriesSecretPreStore(t.X, seen)
	case *ssa.Slice:
		return d.argCarriesSecretPreStore(t.X, seen)
	case *ssa.Phi:
		for _, e := range t.Edges {
			if d.argCarriesSecretPreStore(e, seen) {
				return true
			}
		}
		return false
	case *ssa.UnOp:
		if t.Op == token.MUL {
			root, path, _ := resolveFieldPath(t)
			if p, ok := root.(*ssa.Parameter); ok && d.secretParams[p.Name()] {
				return true
			}
			if _, ok := d.taintedAddrs[root]; ok {
				return true
			}
			for k := range d.fieldTaint[root] {
				if k == path || strings.HasPrefix(path, k+",") || strings.HasPrefix(k, path+",") {
					return true
				}
			}
			return false
		}
		return d.argCarriesSecretPreStore(t.X, seen)
	case *ssa.Call:
		callee := t.Call.StaticCallee()
		if callee != nil {
			if isMACConstructor(callee) {
				return true
			}
			if d.ipAnalyzer != nil && d.ipAnalyzer.IntrinsicReturn(callee) {
				return true
			}
			if d.ipAnalyzer != nil && d.ipAnalyzer.HasTaintedReturn(callee) {
				for _, a := range t.Call.Args {
					if d.argCarriesSecretPreStore(a, seen) {
						return true
					}
				}
			}
		}
		if _, isB := t.Call.Value.(*ssa.Builtin); isB {
			for _, a := range t.Call.Args {
				if d.argCarriesSecretPreStore(a, seen) {
					return true
				}
			}
		}
		return false
	}
	return false
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

// ArgFieldTaint classifies a value's taint for propagation across a call/return
// boundary. whole=true means the value is secret as a whole (a key, a raw MAC,
// an extracted field value, an annotated struct) so the receiving param/result
// and all its field reads are secret. Otherwise it returns the specific struct
// field paths that are tainted, so sibling public fields stay clean.
func (d *Depender) ArgFieldTaint(v ssa.Value) (whole bool, fields []string) {
	if s, _ := d.DependsOn(v); s == "" {
		return false, nil
	}
	root, path, sawIndex := resolveFieldPath(v)
	if path != "" || sawIndex {
		return true, nil // v is itself an extracted secret field/element
	}
	if _, ok := d.taintedAddrs[root]; ok {
		return true, nil // whole-object store
	}
	if d.elementTaintRoots[root] {
		// A secret written into a slice/array element of a field is tracked
		// element-blind, so it cannot be re-seeded precisely across the boundary.
		// Fall back to whole-value taint to preserve container-root propagation.
		return true, nil
	}
	ft := d.fieldTaint[root]
	if len(ft) == 0 {
		return true, nil // tainted but not field-scoped
	}
	for k := range ft {
		fields = append(fields, k)
	}
	return false, fields
}

// copyFieldTaint preserves field-level taint across a whole-struct copy such as
// the SSA `*t0 = r` that spills a by-value struct param/result into a local: the
// secret field stays tainted in the copy while sibling public fields do not.
func (d *Depender) copyFieldTaint(dst, src ssa.Value) {
	srcRoot, srcPath, srcIdx := resolveFieldPath(src)
	if srcPath != "" || srcIdx {
		return
	}
	srcFields := d.fieldTaint[srcRoot]
	if len(srcFields) == 0 {
		return
	}
	dstRoot, dstPath, dstIdx := resolveFieldPath(dst)
	if dstPath != "" || dstIdx {
		return
	}
	for fpath, s := range srcFields {
		d.setFieldTaint(dstRoot, fpath, s)
	}
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
			d.elementTaintRoots[root] = true    // element-level: propagate whole across boundaries
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
				} else {
					d.copyFieldTaint(store.Addr, store.Val)
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
	if s, ok := d.derivedTaint[v]; ok {
		return s, confidence.ConfidenceLow
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
		if callee != nil && isConstantTimeSanitizer(callee) {
			// Constant-time comparison result is a decision, not secret content: sanitize.
			secret = ""
			conf = confidence.ConfidenceLow
		} else if callee != nil && isMACConstructor(callee) {
			// hmac.New(...) returns a keyed MAC state whose output is secret-equivalent
			// regardless of how the key was obtained, so seed taint here. A later
			// mac.Sum() compared in non-constant time is then caught with no annotation.
			secret = "hmac"
			conf = confidence.ConfidenceHigh
		} else if callee != nil && isSyncPoolGet(callee) && d.ipAnalyzer != nil &&
			len(t.Call.Args) > 0 && d.ipAnalyzer.IsMACPool(t.Call.Args[0]) {
			// (*sync.Pool).Get() on a pool whose New returns a MAC yields MAC state,
			// so the pooled hmac.Sum() compared later is caught with no annotation.
			secret = "hmac"
			conf = confidence.ConfidenceHigh
		} else if callee != nil && d.ipAnalyzer != nil && d.ipAnalyzer.IsAnalyzed(callee) {
			// Same-package analyzed callee: trust its return-taint verdict so a secret
			// derived inside the callee (e.g. an HMAC) reaches the caller's result.
			// The result is secret only if justified HERE: either a tainted argument
			// flows in, or the callee's return is intrinsically secret (in-body source
			// or annotated param) independent of arguments. A merely param-derived
			// return with public arguments at this site is NOT secret.
			if d.ipAnalyzer.HasTaintedReturn(callee) {
				if s, c := d.taintFromArgs(t); s != "" {
					secret, conf = s, c
				} else if d.ipAnalyzer.IntrinsicReturn(callee) {
					secret, conf = callee.Name(), confidence.ConfidenceLow
				}
			} else {
				secret = ""
				conf = confidence.ConfidenceLow
			}
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
		} else if t.Call.IsInvoke() {
			// Interface method call such as mac.Sum(nil): the receiver, not the args,
			// carries the taint. Metadata methods (results all numeric/bool/error,
			// e.g. Size or Write) expose no content and stay clean. Arg-derived
			// taint keeps the pre-existing LOW cap for uninspectable callees.
			if s, c := d.DependsOn(t.Call.Value); s != "" && methodYieldsContent(t.Call.Method) {
				secret, conf = s, c
			} else if s, _ := d.taintFromArgs(t); s != "" {
				secret, conf = s, confidence.ConfidenceLow
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

	case *ssa.ChangeInterface:
		// interface-to-interface conversion (e.g. hash.Hash -> any) preserves the
		// underlying value's taint, except widening an error (error -> any, as when
		// wrapping a decode error with fmt.Errorf) which is a diagnostic, not secret
		// content, mirroring the error exemption in methodYieldsContent.
		if types.Identical(t.X.Type(), errorType) {
			secret = ""
			conf = confidence.ConfidenceLow
		} else {
			secret, conf = d.DependsOn(t.X)
		}

	case *ssa.TypeAssert:
		// x.(T): the asserted value carries the taint of x (e.g. a pooled MAC
		// retrieved as `pool.Get().(hash.Hash)`).
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

// constantTimeComparators are functions whose result is a comparison decision, not
// secret content. Excludes ConstantTimeSelect/Copy/XORBytes (results can be secret).
var constantTimeComparators = map[string]map[string]bool{
	"crypto/subtle": {
		"ConstantTimeCompare":  true,
		"ConstantTimeByteEq":   true,
		"ConstantTimeEq":       true,
		"ConstantTimeLessOrEq": true,
	},
	"crypto/hmac": {
		"Equal": true,
	},
}

func isConstantTimeSanitizer(fn *ssa.Function) bool {
	obj := fn.Object()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	return constantTimeComparators[obj.Pkg().Path()][obj.Name()]
}

// isMACConstructor reports whether fn produces a keyed MAC state (hmac.New)
// whose output must be treated as secret regardless of annotations.
func isMACConstructor(fn *ssa.Function) bool {
	obj := fn.Object()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Path() == "crypto/hmac" && obj.Name() == "New"
}

// isSyncPoolGet reports whether fn is (*sync.Pool).Get; whether the pool yields a
// MAC is decided separately by IsMACPool on the receiver.
func isSyncPoolGet(fn *ssa.Function) bool {
	obj := fn.Object()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Path() == "sync" && obj.Name() == "Get"
}

// taintFromArgs returns the first tainted argument's secret and confidence.
func (d *Depender) taintFromArgs(t *ssa.Call) (string, confidence.ConfidenceLevel) {
	for _, a := range t.Call.Args {
		if s, c := d.DependsOn(a); s != "" {
			return s, c
		}
	}
	return "", confidence.ConfidenceLow
}

var errorType = types.Universe.Lookup("error").Type()

// methodYieldsContent reports whether any result of the invoked method can
// carry secret content. Numeric, bool and error results are metadata.
func methodYieldsContent(m *types.Func) bool {
	if m == nil {
		return true
	}
	sig, ok := m.Type().(*types.Signature)
	if !ok {
		return true
	}
	res := sig.Results()
	for i := 0; i < res.Len(); i++ {
		rt := res.At(i).Type()
		if types.Identical(rt, errorType) {
			continue
		}
		if b, ok := rt.Underlying().(*types.Basic); ok &&
			b.Info()&(types.IsNumeric|types.IsBoolean) != 0 {
			continue
		}
		return true
	}
	return false
}

// IsTaintedChannel returns the secret name if the channel is tainted, empty string otherwise.
// The second return value indicates the confidence level.
func (d *Depender) IsTaintedChannel(ch ssa.Value) (string, confidence.ConfidenceLevel) {
	if s, ok := d.taintedAddrs[ch]; ok {
		return s, confidence.ConfidenceLow
	}
	return "", confidence.ConfidenceLow
}
