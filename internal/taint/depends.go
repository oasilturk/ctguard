package taint

import (
	"golang.org/x/tools/go/ssa"
)

// Depender tracks which SSA values depend on secret parameters.
type Depender struct {
	secretParams map[string]bool
	memo         map[ssa.Value]string // stores secret name or "" if not tainted
	inStack      map[ssa.Value]bool
}

func NewDepender(secretParams map[string]bool) *Depender {
	return &Depender{
		secretParams: secretParams,
		memo:         map[ssa.Value]string{},
		inStack:      map[ssa.Value]bool{},
	}
}

func (d *Depender) Depends(v ssa.Value) bool {
	return d.DependsOn(v) != ""
}

// DependsOn returns the name of the secret this value depends on,
// or empty string if it's not tainted.
func (d *Depender) DependsOn(v ssa.Value) string {
	if v == nil {
		return ""
	}
	if secret, ok := d.memo[v]; ok {
		return secret
	}
	if d.inStack[v] {
		return ""
	}
	d.inStack[v] = true
	defer func() { d.inStack[v] = false }()

	// Base case: secret parameter
	if p, ok := v.(*ssa.Parameter); ok {
		if d.secretParams[p.Name()] {
			d.memo[v] = p.Name()
			return p.Name()
		}
	}

	var secret string

	switch t := v.(type) {
	case *ssa.UnOp:
		secret = d.DependsOn(t.X)

	case *ssa.BinOp:
		secret = d.DependsOn(t.X)
		if secret == "" {
			secret = d.DependsOn(t.Y)
		}

	case *ssa.Phi:
		for _, e := range t.Edges {
			if s := d.DependsOn(e); s != "" {
				secret = s
				break
			}
		}

	case *ssa.Call:
		for _, a := range t.Call.Args {
			if s := d.DependsOn(a); s != "" {
				secret = s
				break
			}
		}

	case *ssa.ChangeType:
		secret = d.DependsOn(t.X)

	case *ssa.Convert:
		secret = d.DependsOn(t.X)

	case *ssa.MakeInterface:
		secret = d.DependsOn(t.X)

	case *ssa.Extract:
		secret = d.DependsOn(t.Tuple)

	case *ssa.Field:
		secret = d.DependsOn(t.X)

	case *ssa.FieldAddr:
		secret = d.DependsOn(t.X)

	case *ssa.Index:
		secret = d.DependsOn(t.X)
		if secret == "" {
			secret = d.DependsOn(t.Index)
		}

	case *ssa.IndexAddr:
		secret = d.DependsOn(t.X)
		if secret == "" {
			secret = d.DependsOn(t.Index)
		}

	case *ssa.Slice:
		secret = d.DependsOn(t.X)
		if secret == "" && t.Low != nil {
			secret = d.DependsOn(t.Low)
		}
		if secret == "" && t.High != nil {
			secret = d.DependsOn(t.High)
		}
		if secret == "" && t.Max != nil {
			secret = d.DependsOn(t.Max)
		}

	case *ssa.Lookup:
		secret = d.DependsOn(t.X)
		if secret == "" {
			secret = d.DependsOn(t.Index)
		}
	}

	d.memo[v] = secret
	return secret
}
