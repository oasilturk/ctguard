package analyzer_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/oasilturk/ctguard/internal/analyzer"
)

func TestCTGuard(t *testing.T) {
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

	analysistest.Run(t, abs, analyzer.Analyzer, "a")
}
