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

// TestMAC tests CT002 on HMAC output compared in non-constant time, including
// the zero-annotation and return-boundary cases.
func TestMAC(t *testing.T) {
	testdata := getTestdataPath(t)
	analysistest.Run(t, testdata, analyzer.Analyzer, "mac")
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

// TestArithmetic tests detection of variable-time arithmetic operations
func TestArithmetic(t *testing.T) {
	testdata := getTestdataPath(t)
	analysistest.Run(t, testdata, analyzer.Analyzer, "arithmetic")
}

// TestIsolated tests CT007: tainted values flowing into I/O sinks within isolated regions
func TestIsolated(t *testing.T) {
	testdata := getTestdataPath(t)
	analysistest.Run(t, testdata, analyzer.Analyzer, "isolated")
}

// TestContainerRootTaint tests that secrets written into struct/slice fields
// propagate to the containing value, enabling return-value taint and receiver
// propagation across ctor/method calls (Shamir-style chain).
func TestContainerRootTaint(t *testing.T) {
	testdata := getTestdataPath(t)
	analysistest.Run(t, testdata, analyzer.Analyzer, "containertaint")
}

// TestLengthContent tests that len/cap of secret slices return length-taint
// only, while content access still triggers CT001/CT002. Makeslice with a
// secret size propagates length-taint to len() of the result.
func TestLengthContent(t *testing.T) {
	testdata := getTestdataPath(t)
	analysistest.Run(t, testdata, analyzer.Analyzer, "lengthcontent")
}

// Regression: branching on a constant-time comparison must not trigger CT001.
func TestConstantTimeSanitizer(t *testing.T) {
	testdata := getTestdataPath(t)
	analysistest.Run(t, testdata, analyzer.Analyzer, "constanttime")
}
