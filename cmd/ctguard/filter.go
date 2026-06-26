package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/oasilturk/ctguard/internal/confidence"
)

// validRuleIDs is the set of rule IDs ctguard implements.
var validRuleIDs = map[string]bool{
	"CT001": true, "CT002": true, "CT003": true, "CT004": true,
	"CT005": true, "CT006": true, "CT007": true,
}

// firstUnknownRule returns the first unknown rule ID, or "" if all valid (empty/"all"/"*" ok).
func firstUnknownRule(tokens []string) string {
	for _, tok := range tokens {
		r := strings.ToUpper(strings.TrimSpace(tok))
		if r == "" || r == "ALL" || r == "*" {
			continue
		}
		if !validRuleIDs[r] {
			return strings.TrimSpace(tok)
		}
	}
	return ""
}

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

		// glob with "**" ("vendor/**", "**/*_test.go")
		if matchGlob(pattern, filePath) {
			return true
		}
		// slash-free glob matches a basename at any depth ("*_test.go")
		if !strings.Contains(pattern, "/") && strings.Contains(pattern, "*") {
			if matched, _ := filepath.Match(pattern, filepath.Base(filePath)); matched {
				return true
			}
		}
		// plain literal / dir prefix ("vendor")
		if !strings.ContainsAny(pattern, "*?") {
			if filePath == pattern || strings.HasPrefix(filePath, pattern+"/") {
				return true
			}
		}
	}

	return false
}

// matchGlob matches path against a glob with "**" (zero or more segments); other
// segments use filepath.Match.
func matchGlob(pattern, path string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(path, "/"))
}

func matchSegments(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			rest := pat[1:]
			if len(rest) == 0 {
				return true // trailing "**" consumes the remaining segments
			}
			for i := 0; i <= len(name); i++ {
				if matchSegments(rest, name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		if ok, _ := filepath.Match(pat[0], name[0]); !ok {
			return false
		}
		pat = pat[1:]
		name = name[1:]
	}
	return len(name) == 0
}
