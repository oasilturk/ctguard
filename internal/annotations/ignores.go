package annotations

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Ignores describes which findings should be skipped.
type Ignores struct {
	// LineIgnores maps file:line to a set of rule IDs to ignore (empty set = ignore all)
	LineIgnores map[string]map[string]bool

	// FuncIgnores maps function name to a set of rule IDs to ignore (empty set = ignore all)
	FuncIgnores map[string]map[string]bool
}

// ShouldIgnore reports whether a diagnostic at the given position for the given rule should be ignored.
func (ig *Ignores) ShouldIgnore(fset *token.FileSet, pos token.Pos, ruleID string, funcName string) bool {
	if ig == nil {
		return false
	}

	// Check line-level ignores
	position := fset.Position(pos)
	lineKey := lineKeyFromPosition(position)

	if rules, ok := ig.LineIgnores[lineKey]; ok {
		// Empty map means ignore all rules
		if len(rules) == 0 {
			return true
		}
		if rules[ruleID] {
			return true
		}
	}

	// Also check the previous line (for comments above the statement)
	prevLineKey := prevLineKeyFromPosition(position)
	if rules, ok := ig.LineIgnores[prevLineKey]; ok {
		if len(rules) == 0 {
			return true
		}
		if rules[ruleID] {
			return true
		}
	}

	// Check function-level ignores
	if funcName != "" {
		if rules, ok := ig.FuncIgnores[funcName]; ok {
			if len(rules) == 0 {
				return true
			}
			if rules[ruleID] {
				return true
			}
		}
	}

	return false
}

func ShouldIgnoreFromConfig(ruleID string, ignoredRules []string) bool {
	for _, r := range ignoredRules {
		if r == "all" || r == ruleID {
			return true
		}
	}
	return false
}

func lineKeyFromPosition(pos token.Position) string {
	return pos.Filename + ":" + strconv.Itoa(pos.Line)
}

func prevLineKeyFromPosition(pos token.Position) string {
	if pos.Line > 1 {
		return pos.Filename + ":" + strconv.Itoa(pos.Line-1)
	}
	return ""
}

// CollectIgnores scans all files for //ctguard:ignore directives.
func CollectIgnores(pass *analysis.Pass) Ignores {
	out := Ignores{
		LineIgnores: make(map[string]map[string]bool),
		FuncIgnores: make(map[string]map[string]bool),
	}

	for _, f := range pass.Files {
		// Collect all comments in the file
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				rules := parseIgnoreDirective(c.Text)
				if rules == nil {
					continue // Not an ignore directive
				}

				pos := pass.Fset.Position(c.Pos())
				lineKey := lineKeyFromPosition(pos)
				out.LineIgnores[lineKey] = rules
			}
		}

		// Check function-level ignores (in doc comments)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name == nil || fd.Doc == nil {
				continue
			}

			for _, c := range fd.Doc.List {
				rules := parseIgnoreDirective(c.Text)
				if rules == nil {
					continue
				}

				// This is a function-level ignore
				// Store under simple function name (always works)
				simpleName := fd.Name.Name
				out.FuncIgnores[simpleName] = rules

				// Also store under full method name for methods
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
						out.FuncIgnores[fullName] = rules
					}
				}

				// Also store with full package path if available
				if obj := pass.TypesInfo.Defs[fd.Name]; obj != nil {
					out.FuncIgnores[obj.String()] = rules
				}
			}
		}
	}

	return out
}

// parseIgnoreDirective parses a comment for a //ctguard:ignore directive.
// Returns nil if it is not an ignore directive OR if it is malformed (names no
// recognized rule) so the caller fails closed and ignores nothing.
// Returns an empty map for an explicit ignore-all ("//ctguard:ignore" or "...:ignore all").
// Returns a map with rule IDs for specific rules.
func parseIgnoreDirective(text string) map[string]bool {
	text = strings.TrimSpace(text)

	// Handle line comments
	if strings.HasPrefix(text, "//") {
		text = strings.TrimSpace(strings.TrimPrefix(text, "//"))
	}

	// Must start with ctguard:ignore
	if !strings.HasPrefix(text, "ctguard:ignore") {
		return nil
	}

	text = strings.TrimPrefix(text, "ctguard:ignore")
	text = strings.TrimSpace(text)

	// Remove reason (everything after --)
	if idx := strings.Index(text, "--"); idx >= 0 {
		text = strings.TrimSpace(text[:idx])
	}

	// Bare directive (or "all") ignores every rule.
	if text == "" || strings.EqualFold(text, "all") {
		return make(map[string]bool)
	}

	// Parse rule IDs (comma or space separated)
	rules := make(map[string]bool)
	for _, part := range strings.FieldsFunc(text, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		part = strings.TrimSpace(part)
		if part != "" && strings.HasPrefix(part, "CT") {
			rules[part] = true
		}
	}

	// Fail closed: a non-empty directive that names no recognized rule (a typo like
	// lowercase "ct002", or prose) must ignore nothing, not silently ignore all.
	if len(rules) == 0 {
		return nil
	}

	return rules
}
