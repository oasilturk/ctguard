package annotations

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

type IsolatedRegions struct {
	FuncIsolated map[string]bool

	BlockRegions map[string][]LineRange
}

type LineRange struct {
	Start int
	End   int
}

func (ir *IsolatedRegions) IsIsolated(fset *token.FileSet, pos token.Pos, funcIdentity string) bool {
	if ir == nil {
		return false
	}

	if funcIdentity != "" && ir.FuncIsolated[funcIdentity] {
		return true
	}

	if pos == token.NoPos {
		return false
	}
	position := fset.Position(pos)
	if ranges, ok := ir.BlockRegions[position.Filename]; ok {
		for _, r := range ranges {
			if position.Line >= r.Start && position.Line <= r.End {
				return true
			}
		}
	}

	return false
}

// CollectIsolated scans all files in the pass for //ctguard:isolated directives.
// An unclosed begin (no matching end) is reported as a diagnostic error.
func CollectIsolated(pass *analysis.Pass) IsolatedRegions {
	out := IsolatedRegions{
		FuncIsolated: make(map[string]bool),
		BlockRegions: make(map[string][]LineRange),
	}

	for _, f := range pass.Files {
		collectFuncLevelIsolated(pass, f, &out)
		collectBlockLevelIsolated(pass, f, &out)
	}

	return out
}

func collectFuncLevelIsolated(pass *analysis.Pass, f *ast.File, out *IsolatedRegions) {
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name == nil || fd.Doc == nil {
			continue
		}

		for _, c := range fd.Doc.List {
			kind := parseIsolatedDirective(c.Text)
			if kind != isolatedKindFunc {
				continue
			}

			// store under simple name
			out.FuncIsolated[fd.Name.Name] = true

			// store under fully qualified name (matches fn.String() in SSA)
			// e.g. "mypkg.MyFunc"
			if obj := pass.TypesInfo.Defs[fd.Name]; obj != nil {
				if fnObj, ok := obj.(*types.Func); ok && fnObj != nil {
					out.FuncIsolated[fnObj.FullName()] = true
				}
			}

			// store under method receiver form
			if fd.Recv != nil && len(fd.Recv.List) > 0 {
				var fullName string
				if t, ok := fd.Recv.List[0].Type.(*ast.StarExpr); ok {
					if ident, ok := t.X.(*ast.Ident); ok {
						fullName = "(*" + ident.Name + ")." + fd.Name.Name
					}
				} else if ident, ok := fd.Recv.List[0].Type.(*ast.Ident); ok {
					fullName = ident.Name + "." + fd.Name.Name
				}
				if fullName != "" {
					out.FuncIsolated[fullName] = true
				}
			}
		}
	}
}

func collectBlockLevelIsolated(pass *analysis.Pass, f *ast.File, out *IsolatedRegions) {
	// track open begin positions per file: filename -> stack of begin line numbers
	type openBegin struct {
		pos  token.Pos
		line int
	}
	openBegins := map[string][]openBegin{}

	for _, cg := range f.Comments {
		for _, c := range cg.List {
			kind := parseIsolatedDirective(c.Text)
			if kind == isolatedKindNone {
				continue
			}

			pos := c.Pos()
			position := pass.Fset.Position(pos)
			filename := position.Filename

			switch kind {
			case isolatedKindBegin:
				openBegins[filename] = append(openBegins[filename], openBegin{
					pos:  pos,
					line: position.Line,
				})

			case isolatedKindEnd:
				stack := openBegins[filename]
				if len(stack) == 0 {
					// end without begin, report but continue
					pass.Reportf(pos, "ctguard:isolated end without matching begin")
					continue
				}
				// pop the last open begin
				last := stack[len(stack)-1]
				openBegins[filename] = stack[:len(stack)-1]

				out.BlockRegions[filename] = append(out.BlockRegions[filename], LineRange{
					Start: last.line,
					End:   position.Line,
				})
			}
		}
	}

	// report any unclosed begin directives
	for _, stack := range openBegins {
		for _, ob := range stack {
			pass.Reportf(ob.pos, "ctguard:isolated begin without matching end")
		}
	}
}

type isolatedKind int

const (
	isolatedKindNone  isolatedKind = iota
	isolatedKindFunc               // //ctguard:isolated  (no suffix)
	isolatedKindBegin              // //ctguard:isolated begin
	isolatedKindEnd                // //ctguard:isolated end
)

func parseIsolatedDirective(text string) isolatedKind {
	text = strings.TrimSpace(text)

	if strings.HasPrefix(text, "//") {
		text = strings.TrimSpace(strings.TrimPrefix(text, "//"))
	} else {
		return isolatedKindNone
	}

	if !strings.HasPrefix(text, "ctguard:isolated") {
		return isolatedKindNone
	}

	rest := strings.TrimSpace(strings.TrimPrefix(text, "ctguard:isolated"))

	if idx := strings.Index(rest, "--"); idx >= 0 {
		rest = strings.TrimSpace(rest[:idx])
	}

	switch rest {
	case "":
		return isolatedKindFunc
	case "begin":
		return isolatedKindBegin
	case "end":
		return isolatedKindEnd
	default:
		return isolatedKindNone
	}
}
