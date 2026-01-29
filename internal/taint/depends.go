package taint

import (
	"golang.org/x/tools/go/ssa"
)

// Depender answers: "Does v depend on any secret parameter?"
// secretParams is a set of parameter names, e.g. {"k":true}.
type Depender struct {
	secretParams map[string]bool
	memo         map[ssa.Value]bool
	inStack      map[ssa.Value]bool
}

func NewDepender(secretParams map[string]bool) *Depender {
	return &Depender{
		secretParams: secretParams,
		memo:         map[ssa.Value]bool{},
		inStack:      map[ssa.Value]bool{},
	}
}

func (d *Depender) Depends(v ssa.Value) bool {
	if v == nil {
		return false
	}
	if val, ok := d.memo[v]; ok {
		return val
	}
	if d.inStack[v] {
		return false
	}
	d.inStack[v] = true
	defer func() { d.inStack[v] = false }()

	// Base case: secret parameter
	if p, ok := v.(*ssa.Parameter); ok {
		if d.secretParams[p.Name()] {
			d.memo[v] = true
			return true
		}
	}

	switch t := v.(type) {
	case *ssa.UnOp:
		d.memo[v] = d.Depends(t.X)
		return d.memo[v]

	case *ssa.BinOp:
		d.memo[v] = d.Depends(t.X) || d.Depends(t.Y)
		return d.memo[v]

	case *ssa.Phi:
		for _, e := range t.Edges {
			if d.Depends(e) {
				d.memo[v] = true
				return true
			}
		}
		d.memo[v] = false
		return false

	case *ssa.Call:
		for _, a := range t.Call.Args {
			if d.Depends(a) {
				d.memo[v] = true
				return true
			}
		}
		d.memo[v] = false
		return false

	case *ssa.ChangeType:
		d.memo[v] = d.Depends(t.X)
		return d.memo[v]

	case *ssa.Convert:
		d.memo[v] = d.Depends(t.X)
		return d.memo[v]

	case *ssa.MakeInterface:
		d.memo[v] = d.Depends(t.X)
		return d.memo[v]

	case *ssa.Extract:
		d.memo[v] = d.Depends(t.Tuple)
		return d.memo[v]

	case *ssa.Field:
		d.memo[v] = d.Depends(t.X)
		return d.memo[v]

	case *ssa.FieldAddr:
		d.memo[v] = d.Depends(t.X)
		return d.memo[v]

	case *ssa.Index:
		d.memo[v] = d.Depends(t.X) || d.Depends(t.Index)
		return d.memo[v]

	case *ssa.IndexAddr:
		d.memo[v] = d.Depends(t.X) || d.Depends(t.Index)
		return d.memo[v]

	case *ssa.Slice:
		ok := d.Depends(t.X)
		if t.Low != nil {
			ok = ok || d.Depends(t.Low)
		}
		if t.High != nil {
			ok = ok || d.Depends(t.High)
		}
		if t.Max != nil {
			ok = ok || d.Depends(t.Max)
		}
		d.memo[v] = ok
		return ok

	case *ssa.Lookup:
		d.memo[v] = d.Depends(t.X) || d.Depends(t.Index)
		return d.memo[v]
	default:
		d.memo[v] = false
		return false
	}
}
