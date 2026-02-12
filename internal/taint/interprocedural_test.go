package taint

import (
	"go/parser"
	"go/token"
	"testing"

	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/loader" //nolint:staticcheck // Test helper, loader is simpler for test scenarios
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/oasilturk/ctguard/internal/annotations"
)

func TestInterproceduralAnalyzer_BasicPropagation(t *testing.T) {
	src := `
package test

func Caller(secret int) int {
	return Helper(secret)
}

func Helper(n int) int {
	return n * 2
}
`

	ssaRes, err := buildTestSSA(src)
	if err != nil {
		t.Fatalf("Failed to build SSA: %v", err)
	}

	// Mark Caller's "secret" parameter as secret
	secrets := annotations.Secrets{
		FuncSecretParams: map[string]map[string]bool{
			"test.Caller": {"secret": true},
		},
	}

	ia := NewInterproceduralAnalyzer(ssaRes, secrets)
	if ia == nil {
		t.Fatal("NewInterproceduralAnalyzer returned nil")
	}

	// Before analysis, Helper should not have tainted params
	helperFn := findFunction(ssaRes, "Helper")
	if helperFn == nil {
		t.Fatal("Could not find Helper function")
	}

	secretsBefore := ia.GetSecretParams(helperFn)
	if secretsBefore["n"] {
		t.Error("Helper's 'n' should not be tainted before analysis")
	}

	// Run analysis
	ia.Analyze()

	// After analysis, Helper's "n" should be tainted
	secretsAfter := ia.GetSecretParams(helperFn)
	if !secretsAfter["n"] {
		t.Error("Helper's 'n' should be tainted after interprocedural analysis")
	}
}

func TestInterproceduralAnalyzer_MultiLevel(t *testing.T) {
	src := `
package test

func Level1(secret int) int {
	return Level2(secret)
}

func Level2(a int) int {
	return Level3(a)
}

func Level3(b int) int {
	return b + 1
}
`

	ssaRes, err := buildTestSSA(src)
	if err != nil {
		t.Fatalf("Failed to build SSA: %v", err)
	}

	secrets := annotations.Secrets{
		FuncSecretParams: map[string]map[string]bool{
			"test.Level1": {"secret": true},
		},
	}

	ia := NewInterproceduralAnalyzer(ssaRes, secrets)
	ia.Analyze()

	// Check Level2
	level2 := findFunction(ssaRes, "Level2")
	if level2 == nil {
		t.Fatal("Could not find Level2")
	}
	if !ia.GetSecretParams(level2)["a"] {
		t.Error("Level2's 'a' should be tainted")
	}

	// Check Level3
	level3 := findFunction(ssaRes, "Level3")
	if level3 == nil {
		t.Fatal("Could not find Level3")
	}
	if !ia.GetSecretParams(level3)["b"] {
		t.Error("Level3's 'b' should be tainted")
	}
}

func TestInterproceduralAnalyzer_NoAnnotation(t *testing.T) {
	src := `
package test

func Foo(x int) int {
	return Bar(x)
}

func Bar(y int) int {
	return y * 2
}
`

	ssaRes, err := buildTestSSA(src)
	if err != nil {
		t.Fatalf("Failed to build SSA: %v", err)
	}

	// No secrets annotated
	secrets := annotations.Secrets{
		FuncSecretParams: map[string]map[string]bool{},
	}

	ia := NewInterproceduralAnalyzer(ssaRes, secrets)
	ia.Analyze()

	// Nothing should be tainted
	barFn := findFunction(ssaRes, "Bar")
	if barFn == nil {
		t.Fatal("Could not find Bar")
	}

	if ia.GetSecretParams(barFn)["y"] {
		t.Error("Bar's 'y' should not be tainted (no annotation)")
	}
}

func TestInterproceduralAnalyzer_GetSecretParams_UnknownFunction(t *testing.T) {
	src := `package test
func Dummy() {}`

	ssaRes, err := buildTestSSA(src)
	if err != nil {
		t.Fatalf("Failed to build SSA: %v", err)
	}

	secrets := annotations.Secrets{
		FuncSecretParams: map[string]map[string]bool{},
	}

	ia := NewInterproceduralAnalyzer(ssaRes, secrets)

	// Create a fake function not in the analyzer
	fakeFn := &ssa.Function{}
	params := ia.GetSecretParams(fakeFn)

	if params == nil {
		t.Error("GetSecretParams should return empty map, not nil")
	}

	if len(params) != 0 {
		t.Errorf("Expected empty params, got %v", params)
	}
}

// Helper function to build SSA from source code
func buildTestSSA(src string) (*buildssa.SSA, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	// Use go/loader for simpler SSA construction
	conf := loader.Config{
		Fset: fset,
	}
	conf.CreateFromFiles("test", file)

	lprog, err := conf.Load()
	if err != nil {
		return nil, err
	}

	prog := ssautil.CreateProgram(lprog, ssa.SanityCheckFunctions) //nolint:staticcheck // Test helper
	prog.Build()

	pkg := prog.Package(lprog.Package("test").Pkg)
	if pkg == nil {
		return nil, err
	}

	pkg.Build()

	// Create buildssa.SSA result
	allFuncs := ssautil.AllFunctions(prog)
	srcFuncs := make([]*ssa.Function, 0, len(allFuncs))
	for fn := range allFuncs {
		if fn != nil {
			srcFuncs = append(srcFuncs, fn)
		}
	}

	result := &buildssa.SSA{
		Pkg:      pkg,
		SrcFuncs: srcFuncs,
	}

	return result, nil
}

// Helper to find a function by name
func findFunction(ssaRes *buildssa.SSA, name string) *ssa.Function {
	for _, fn := range ssaRes.SrcFuncs {
		if fn != nil && fn.Name() == name {
			return fn
		}
	}
	return nil
}
