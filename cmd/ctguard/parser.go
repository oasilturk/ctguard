package main

import (
	"encoding/json"
	"strings"

	"github.com/oasilturk/ctguard/internal/confidence"
)

func parseGoVetJSON(s string) []Finding {
	var out []Finding

	// go vet -json outputs multiple JSON objects when analyzing multiple packages:
	// # pkg1
	// { json1 }
	// # pkg2
	// { json2 }
	// We need to parse each JSON object separately.

	jsonObjects := extractJSONObjects(s)
	if len(jsonObjects) == 0 {
		return out
	}

	for _, jsonStr := range jsonObjects {
		var m map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
			continue // Skip malformed JSON, try others
		}

		for _, pkgVal := range m {
			pkgMap, ok := pkgVal.(map[string]any)
			if !ok {
				continue
			}
			for _, analyzerVal := range pkgMap {
				diagnostics, ok := analyzerVal.([]any)
				if !ok {
					continue
				}
				for _, diagVal := range diagnostics {
					diag, ok := diagVal.(map[string]any)
					if !ok {
						continue
					}
					msg, _ := diag["message"].(string)
					if msg == "" {
						continue
					}
					pos := ""
					if p, _ := diag["posn"].(string); p != "" {
						pos = p
					} else if p, _ := diag["pos"].(string); p != "" {
						pos = p
					}
					out = append(out, Finding{
						Pos:        pos,
						Message:    msg,
						Rule:       extractRule(msg),
						Confidence: extractConfidence(msg),
					})
				}
			}
		}
	}

	return out
}

// extractJSONObjects finds all top-level JSON objects in the input string.
// go vet -json outputs one JSON object per package, each on separate lines.
func extractJSONObjects(s string) []string {
	var objects []string
	depth := 0
	start := -1

	for i, ch := range s {
		switch ch {
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 && start >= 0 {
				objects = append(objects, s[start:i+1])
				start = -1
			}
		}
	}

	return objects
}

func extractRule(msg string) string {
	i := strings.Index(msg, ":")
	if i <= 0 {
		return ""
	}
	prefix := strings.TrimSpace(msg[:i])
	if strings.HasPrefix(prefix, "CT") {
		return prefix
	}
	return ""
}

func extractConfidence(msg string) string {
	tag := confidence.ConfidenceTag
	idx := strings.Index(msg, tag)
	if idx < 0 {
		return ""
	}
	rest := msg[idx+len(tag):]
	// confidence value ends at ')' or end of string
	if end := strings.IndexByte(rest, ')'); end >= 0 {
		return rest[:end]
	}
	return strings.TrimSpace(rest)
}
