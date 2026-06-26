package main

import (
	"encoding/json"
	"strings"

	"github.com/oasilturk/ctguard/internal/confidence"
)

// parseGoVetFindings parses go vet -json output (stdout on Go 1.26+, stderr before).
func parseGoVetFindings(stdout, stderr string) []Finding {
	if findings := parseGoVetJSON(stdout); len(findings) > 0 {
		return findings
	}
	return parseGoVetJSON(stderr)
}

// goVetPlainErrors returns go vet's non-JSON error lines (compiler/loader errors).
func goVetPlainErrors(stdout, stderr string) []string {
	var out []string
	for _, s := range []string{stdout, stderr} {
		_, plain := scanGoVetOutput(s)
		for _, ln := range plain {
			t := strings.TrimSpace(ln)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			out = append(out, t)
		}
	}
	return out
}

// goVetParseFailed reports whether a block that scanned as JSON failed to decode,
// so the caller can fail closed instead of dropping findings silently.
func goVetParseFailed(stdout, stderr string) bool {
	for _, s := range []string{stdout, stderr} {
		objs, _ := scanGoVetOutput(s)
		for _, o := range objs {
			var m map[string]any
			if json.Unmarshal([]byte(o), &m) != nil {
				return true
			}
		}
	}
	return false
}

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
	objects, _ := scanGoVetOutput(s)
	return objects
}

// scanGoVetOutput splits go vet output into JSON objects (diagnostics) and plain
// lines (headers, build errors). Boundaries use jsonObjectLen, not a textual brace
// count, so a brace in an error message or a "posn" path can't drop findings.
func scanGoVetOutput(s string) (jsonObjects, plainLines []string) {
	i := 0
	for i < len(s) {
		lineEnd := len(s) // index of '\n' (exclusive), or end of input
		next := len(s)    // start of the following line
		if nl := strings.IndexByte(s[i:], '\n'); nl >= 0 {
			lineEnd = i + nl
			next = i + nl + 1
		}
		line := strings.TrimRight(s[i:lineEnd], "\r")

		if strings.HasPrefix(strings.TrimSpace(line), "{") {
			objStart := i + strings.IndexByte(s[i:lineEnd], '{')
			if n := jsonObjectLen(s[objStart:]); n > 0 {
				jsonObjects = append(jsonObjects, s[objStart:objStart+n])
				i = objStart + n
				if i < len(s) && s[i] == '\n' {
					i++
				}
				continue
			}
		}
		plainLines = append(plainLines, line)
		i = next
	}
	return jsonObjects, plainLines
}

// jsonObjectLen returns the byte length of the JSON object at s[0] ('{'), ignoring
// braces inside strings; 0 if it never closes.
func jsonObjectLen(s string) int {
	depth := 0
	inStr := false
	esc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return 0
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
