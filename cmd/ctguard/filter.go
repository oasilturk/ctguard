package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/oasilturk/ctguard/internal/confidence"
)

func enabledRuleSet(s string) map[string]bool {
	out := map[string]bool{}
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "all") || s == "*" {
		return map[string]bool{}
	}
	for _, p := range strings.Split(s, ",") {
		r := strings.ToUpper(strings.TrimSpace(p))
		if r != "" {
			out[r] = true
		}
	}
	return out
}

func filterFindings(in []Finding, enabled map[string]bool, minConfidence confidence.ConfidenceLevel) []Finding {
	if len(enabled) == 0 && minConfidence == confidence.ConfidenceLow {
		return in
	}
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		if len(enabled) > 0 {
			if f.Rule == "" {
				continue
			}
			if !enabled[f.Rule] {
				continue
			}
		}
		if minConfidence == confidence.ConfidenceHigh {
			if f.Confidence != confidence.ConfidenceHigh.String() {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

func filterExcludedPaths(findings []Finding, excludePatterns []string) []Finding {
	if len(excludePatterns) == 0 {
		return findings
	}

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if shouldExclude(f.Pos, excludePatterns) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func shouldExclude(pos string, patterns []string) bool {
	if pos == "" {
		return false
	}

	// Extract file path from position (format: "file:line:col")
	filePath := pos
	if idx := strings.Index(pos, ":"); idx > 0 {
		filePath = pos[:idx]
	}

	// Normalize path separators and make relative
	filePath = filepath.Clean(filePath)
	if cwd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(cwd, filePath); err == nil {
			filePath = rel
		}
	}

	// Check against each pattern
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		// Remove quotes if present
		pattern = strings.Trim(pattern, `"'`)

		// Handle different pattern types
		if strings.HasSuffix(pattern, "/**") {
			// "vendor/**" matches "vendor/anything"
			prefix := strings.TrimSuffix(pattern, "/**")
			if strings.HasPrefix(filePath, prefix+"/") || filePath == prefix {
				return true
			}
		} else if strings.HasPrefix(pattern, "**/") {
			// "**/test.go" matches "any/path/test.go"
			suffix := strings.TrimPrefix(pattern, "**/")
			if strings.HasSuffix(filePath, suffix) || strings.Contains(filePath, "/"+suffix) {
				return true
			}
		} else if strings.Contains(pattern, "*") {
			// Use filepath.Match for glob patterns
			if matched, _ := filepath.Match(pattern, filepath.Base(filePath)); matched {
				return true
			}
			// Also try matching the full path
			if matched, _ := filepath.Match(pattern, filePath); matched {
				return true
			}
		} else {
			// Exact match or prefix match
			if filePath == pattern || strings.HasPrefix(filePath, pattern+"/") {
				return true
			}
		}
	}

	return false
}
