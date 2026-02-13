package taint

import (
	"go/token"

	"golang.org/x/tools/go/ssa"
)

// Depender tracks which SSA values depend on secret parameters.
type Depender struct {
	secretParams map[string]bool
	memo         map[ssa.Value]string // stores secret name or "" if not tainted
	inStack      map[ssa.Value]bool
	taintedAddrs map[ssa.Value]string // tracks memory addresses that store tainted values
}

func NewDepender(fn *ssa.Function, secretParams map[string]bool) *Depender {
	d := &Depender{
		secretParams: secretParams,
		memo:         map[ssa.Value]string{},
		inStack:      map[ssa.Value]bool{},
		taintedAddrs: map[ssa.Value]string{},
	}
	d.analyzeStores(fn)
	return d
}

func (d *Depender) Depends(v ssa.Value) bool {
	return d.DependsOn(v) != ""
}

// analyzeStores tracks tainted memory locations from Store, MapUpdate, and append operations.
func (d *Depender) analyzeStores(fn *ssa.Function) {
	if fn == nil || fn.Blocks == nil {
		return
	}

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			if store, ok := instr.(*ssa.Store); ok {
				secret := d.DependsOn(store.Val)
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
				secret := d.DependsOn(mapUpdate.Value)
				if secret == "" {
					continue
				}

				d.taintedAddrs[mapUpdate.Map] = secret
				continue
			}

			if call, ok := instr.(*ssa.Call); ok {
				if builtin, ok := call.Call.Value.(*ssa.Builtin); ok && builtin.Name() == "append" {
					for _, arg := range call.Call.Args {
						if secret := d.DependsOn(arg); secret != "" {
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

	if p, ok := v.(*ssa.Parameter); ok {
		if d.secretParams[p.Name()] {
			d.memo[v] = p.Name()
			return p.Name()
		}
	}

	var secret string

	switch t := v.(type) {
	case *ssa.UnOp:
		if t.Op == token.MUL { // * as in pointer dereference
			addr := t.X
			if s, ok := d.taintedAddrs[addr]; ok {
				secret = s
			}

			if secret == "" {
				switch addrVal := addr.(type) {
				case *ssa.IndexAddr:
					if s, ok := d.taintedAddrs[addrVal.X]; ok {
						secret = s
					}
				case *ssa.FieldAddr:
					if s, ok := d.taintedAddrs[addrVal.X]; ok {
						secret = s
					}
				}
			}

			if secret == "" {
				secret = d.DependsOn(addr)
			}
		} else {
			secret = d.DependsOn(t.X)
		}

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
		if s, ok := d.taintedAddrs[t.X]; ok {
			secret = s
		}
		if secret == "" {
			secret = d.DependsOn(t.X)
		}

	case *ssa.FieldAddr:
		secret = d.DependsOn(t.X)

	case *ssa.Index:
		if s, ok := d.taintedAddrs[t.X]; ok {
			secret = s
		}
		if secret == "" {
			secret = d.DependsOn(t.X)
		}
		if secret == "" {
			secret = d.DependsOn(t.Index)
		}

	case *ssa.IndexAddr:
		if s, ok := d.taintedAddrs[t.X]; ok {
			secret = s
		}
		if secret == "" {
			secret = d.DependsOn(t.X)
		}
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
		if s, ok := d.taintedAddrs[t.X]; ok {
			secret = s
		}
		if secret == "" {
			secret = d.DependsOn(t.X)
		}
		if secret == "" {
			secret = d.DependsOn(t.Index)
		}

	case *ssa.Alloc:
		if s, ok := d.taintedAddrs[t]; ok {
			secret = s
		}
	}

	d.memo[v] = secret
	return secret
}
