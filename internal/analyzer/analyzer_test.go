package analyzer_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/oasilturk/ctguard/internal/analyzer"
)

func getTestdataPath(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to locate test file path")
	}

	// thisFile: .../internal/analyzer/analyzer_test.go
	// root testdata is at: .../testdata
	testdata := filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata")

	abs, err := filepath.Abs(testdata)
	if err != nil {
		t.Fatalf("failed to make testdata path absolute: %v", err)
	}

	return abs
}

// TestCTGuard runs the basic test cases
func TestCTGuard(t *testing.T) {
	testdata := getTestdataPath(t)
	analysistest.Run(t, testdata, analyzer.Analyzer, "branches", "comparisons")
}

// TestNestedBranches tests detection of nested secret-dependent branches
func TestNestedBranches(t *testing.T) {
	testdata := getTestdataPath(t)
	analysistest.Run(t, testdata, analyzer.Analyzer, "nested")
}

// TestTaintPropagation tests that taint flows through operations
func TestTaintPropagation(t *testing.T) {
	testdata := getTestdataPath(t)
	analysistest.Run(t, testdata, analyzer.Analyzer, "propagation")
}

// TestCleanCode tests that safe code produces no warnings
func TestCleanCode(t *testing.T) {
	testdata := getTestdataPath(t)
	analysistest.Run(t, testdata, analyzer.Analyzer, "clean")
}

// TestEdgeCases tests edge cases and special scenarios
func TestEdgeCases(t *testing.T) {
	testdata := getTestdataPath(t)
	analysistest.Run(t, testdata, analyzer.Analyzer, "edge")
}
