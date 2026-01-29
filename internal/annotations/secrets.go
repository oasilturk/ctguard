package annotations

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

type Secrets struct {
	// Key: function identity string (we store both FullName and String for robustness).
	// Value: set of parameter names marked secret for that function.
	FuncSecretParams map[string]map[string]bool
}

func CollectSecrets(pass *analysis.Pass) Secrets {
	out := Secrets{
		FuncSecretParams: map[string]map[string]bool{},
	}

	for _, f := range pass.Files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name == nil || fd.Doc == nil {
				continue
			}

			secretParamNames := parseSecretDirective(fd.Doc)
			if len(secretParamNames) == 0 {
				continue
			}

			obj := pass.TypesInfo.Defs[fd.Name]
			fnObj, ok := obj.(*types.Func)
			if !ok || fnObj == nil {
				continue
			}

			set := map[string]bool{}
			for _, n := range secretParamNames {
				set[n] = true
			}

			// Store under both keys to avoid identity mismatches between AST/types and SSA.
			out.FuncSecretParams[fnObj.FullName()] = set
			out.FuncSecretParams[fnObj.String()] = set
		}
	}

	return out
}

func parseSecretDirective(cg *ast.CommentGroup) []string {
	if cg == nil {
		return nil
	}
	var out []string

	for _, c := range cg.List {
		raw := strings.TrimSpace(c.Text)

		// Line comments: // ...
		if strings.HasPrefix(raw, "//") {
			raw = strings.TrimSpace(strings.TrimPrefix(raw, "//"))
			out = append(out, parseLine(raw)...)
			continue
		}

		// Block comments: /* ... */
		if strings.HasPrefix(raw, "/*") {
			raw = strings.TrimSpace(strings.TrimPrefix(raw, "/*"))
			raw = strings.TrimSpace(strings.TrimSuffix(raw, "*/"))
			lines := strings.Split(raw, "\n")
			for _, ln := range lines {
				ln = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ln), "*"))
				out = append(out, parseLine(ln)...)
			}
			continue
		}
	}

	return out
}

func parseLine(line string) []string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "ctguard:secret") {
		return nil
	}
	parts := strings.Fields(line)
	if len(parts) <= 1 {
		return nil
	}
	return parts[1:]
}
