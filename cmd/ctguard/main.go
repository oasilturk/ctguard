package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"

	"golang.org/x/tools/go/analysis/unitchecker"

	"github.com/oasilturk/ctguard/internal/analyzer"
)

// Build info (set via ldflags or read from debug.BuildInfo)
var (
	version = "dev"
	commit  = "unknown"
)

const vettoolEnv = "CTGUARD_VETTOOL"

// ANSI color codes
type colors struct {
	Reset   string
	Bold    string
	Red     string
	Green   string
	Yellow  string
	Blue    string
	Magenta string
	Cyan    string
	Gray    string
}

var noColors = colors{}

var ansiColors = colors{
	Reset:   "\033[0m",
	Bold:    "\033[1m",
	Red:     "\033[31m",
	Green:   "\033[32m",
	Yellow:  "\033[33m",
	Blue:    "\033[34m",
	Magenta: "\033[35m",
	Cyan:    "\033[36m",
	Gray:    "\033[90m",
}

var c colors

func init() {
	// Enable colors if stdout is a terminal and NO_COLOR is not set
	if isTerminal() && os.Getenv("NO_COLOR") == "" {
		c = ansiColors
	} else {
		c = noColors
	}

	// Try to get version from build info
	if version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if info.Main.Version != "" && info.Main.Version != "(devel)" {
				version = info.Main.Version
			}
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" && len(s.Value) >= 7 {
					commit = s.Value[:7]
				}
			}
		}
	}
}

func isTerminal() bool {
	if fi, err := os.Stdout.Stat(); err == nil {
		return (fi.Mode() & os.ModeCharDevice) != 0
	}
	return false
}

type Finding struct {
	Pos     string `json:"pos"`
	Message string `json:"message"`
	Rule    string `json:"rule,omitempty"`
}

func main() {
	// go vet -vettool=<this binary> calls us; we switch into vettool mode via env.
	if os.Getenv(vettoolEnv) == "1" {
		unitchecker.Main(analyzer.Analyzer)
		return
	}
	os.Exit(runCLI(os.Args[1:]))
}

func printHelp() {
	fmt.Printf(`%s%sCTGuard%s - Detect timing side-channel vulnerabilities in Go code

%sUSAGE%s
    ctguard [flags] [packages...]

%sEXAMPLES%s
    ctguard ./...                      %s# Scan entire project%s
    ctguard -rules=CT001 ./pkg/...     %s# Only check for secret-dependent branches%s
    ctguard -format=json ./...         %s# JSON output for CI integration%s
    ctguard -fail=false ./...          %s# Don't fail on findings (for reports)%s

%sFLAGS%s
    -format string    Output format: plain or json (default "plain")
    -rules string     Comma-separated rule IDs or 'all' (default "all")
    -fail             Exit with code 1 if findings exist (default true)
    -quiet            Suppress diagnostic output
    -summary          Print summary after diagnostics (default true)
    -version          Show version information
    -help             Show this help message

%sRULES%s
    %sCT001%s  Secret-dependent branches
           Detects control flow that depends on secret data, which can
           leak information through timing differences.

    %sCT002%s  Non-constant-time comparisons  
           Detects use of bytes.Equal, strings.Compare, == on strings,
           and similar operations with secret data. Use crypto/subtle
           for constant-time comparisons.

    %sCT003%s  Secret-dependent indexing
           Detects array, slice, and map indexing where the index
           depends on secret data. This can leak information through
           cache-timing side-channels (e.g., S-box lookups).

%sANNOTATIONS%s
    Mark function parameters as secret using comments:

        //ctguard:secret key
        func Verify(key []byte, data []byte) bool { ... }

%sENVIRONMENT%s
    NO_COLOR    Set to disable colored output

%sLEARN MORE%s
    https://github.com/oasilturk/ctguard

`,
		c.Bold, c.Cyan, c.Reset,
		c.Bold, c.Reset,
		c.Bold, c.Reset,
		c.Gray, c.Reset,
		c.Gray, c.Reset,
		c.Gray, c.Reset,
		c.Gray, c.Reset,
		c.Bold, c.Reset,
		c.Bold, c.Reset,
		c.Yellow, c.Reset,
		c.Yellow, c.Reset,
		c.Yellow, c.Reset,
		c.Bold, c.Reset,
		c.Bold, c.Reset,
		c.Bold, c.Reset,
	)
}

func printVersion() {
	// Clean up pseudo-version for display
	displayVersion := version
	if strings.Contains(displayVersion, "-") && len(displayVersion) > 20 {
		// Likely a pseudo-version like v0.0.0-20260129144757-ae706417eede
		// Just show "dev" instead
		displayVersion = "dev"
	}

	fmt.Printf("%s%sctguard%s %s%s%s", c.Bold, c.Cyan, c.Reset, c.Bold, displayVersion, c.Reset)
	if commit != "unknown" {
		fmt.Printf(" %s(%s)%s", c.Gray, commit, c.Reset)
	}
	fmt.Println()
}

func runCLI(args []string) int {
	// Handle help and version before flag parsing
	for _, arg := range args {
		switch arg {
		case "-h", "-help", "--help":
			printHelp()
			return 0
		case "-v", "-version", "--version":
			printVersion()
			return 0
		}
	}

	var (
		format  string
		rules   string
		fail    bool
		quiet   bool
		summary bool
	)

	// Manual flag parsing to avoid flag package's default behavior
	var patterns []string
	for i := 0; i < len(args); i++ {
		arg := args[i]

		if !strings.HasPrefix(arg, "-") {
			patterns = append(patterns, arg)
			continue
		}

		// Handle -flag=value and -flag value formats
		key, value, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")

		getValue := func() (string, bool) {
			if hasValue {
				return value, true
			}
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				return args[i], true
			}
			return "", false
		}

		switch key {
		case "format":
			if v, ok := getValue(); ok {
				format = v
			}
		case "rules":
			if v, ok := getValue(); ok {
				rules = v
			}
		case "fail":
			if hasValue {
				fail = value == "true"
			} else {
				fail = true
			}
		case "quiet":
			if hasValue {
				quiet = value == "true"
			} else {
				quiet = true
			}
		case "summary":
			if hasValue {
				summary = value == "true"
			} else {
				summary = true
			}
		default:
			fmt.Fprintf(os.Stderr, "%s%serror:%s unknown flag: %s\n", c.Bold, c.Red, c.Reset, arg)
			fmt.Fprintf(os.Stderr, "Run 'ctguard --help' for usage.\n")
			return 2
		}
	}

	// Apply defaults
	if format == "" {
		format = "plain"
	}
	if rules == "" {
		rules = "all"
	}
	if !fail && !containsFlag(args, "fail") {
		fail = true
	}
	if !summary && !containsFlag(args, "summary") {
		summary = true
	}

	// Validate format
	if format != "plain" && format != "json" {
		fmt.Fprintf(os.Stderr, "%s%serror:%s -format must be 'plain' or 'json'\n", c.Bold, c.Red, c.Reset)
		return 2
	}

	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s%serror:%s cannot determine executable path: %v\n", c.Bold, c.Red, c.Reset, err)
		return 2
	}
	exe, _ = filepath.Abs(exe)

	// We do NOT pass -ctguard.rules to go vet. Rule filtering happens in this runner.
	goArgs := []string{"vet", "-json", "-vettool=" + exe}
	goArgs = append(goArgs, patterns...)

	cmd := exec.Command("go", goArgs...)
	cmd.Env = append(os.Environ(), vettoolEnv+"=1")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	exitCode := exitCodeFromErr(runErr)

	// go vet -json writes JSON diagnostics to stderr, not stdout
	allFindings, _ := parseGoVetJSON(stderr.String())

	enabled := enabledRuleSet(rules)
	findings := filterFindings(allFindings, enabled)

	// "Real error" means: go vet failed AND produced no findings at all (likely build/toolchain error).
	toolErr := exitCode != 0 && len(allFindings) == 0

	// Print diagnostics (ONLY our filtered findings; never forward go vet's JSON noise)
	if !quiet {
		if format == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(findings)
		} else {
			printPlain(findings)
		}
	}

	// Forward stderr only on real tool/build errors (but not JSON output).
	if toolErr {
		for _, line := range strings.Split(stderr.String(), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "{") || strings.HasPrefix(line, "}") ||
				strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "]") {
				continue
			}
			fmt.Fprintf(os.Stderr, "%s%serror:%s %s\n", c.Bold, c.Red, c.Reset, line)
		}
	}

	// Summary (keep JSON clean -> summary to stderr if format=json)
	if summary {
		printSummary(findings, format == "json")
	}

	// Exit code policy:
	// - If real tool/build error -> propagate.
	// - Otherwise, base result on (filtered) findings + -fail flag.
	if toolErr {
		return exitCode
	}

	if len(findings) > 0 && fail {
		return 1
	}
	return 0
}

func containsFlag(args []string, flag string) bool {
	for _, arg := range args {
		if strings.Contains(arg, flag) {
			return true
		}
	}
	return false
}

func exitCodeFromErr(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return 1
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

func filterFindings(in []Finding, enabled map[string]bool) []Finding {
	if len(enabled) == 0 {
		return in
	}
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		if f.Rule == "" {
			continue
		}
		if enabled[f.Rule] {
			out = append(out, f)
		}
	}
	return out
}

func printPlain(findings []Finding) {
	for _, f := range findings {
		rule := f.Rule
		if rule == "" {
			rule = "???"
		}

		// Color the rule based on type
		ruleColor := c.Yellow
		if strings.HasPrefix(rule, "CT001") {
			ruleColor = c.Magenta
		} else if strings.HasPrefix(rule, "CT002") {
			ruleColor = c.Cyan
		} else if strings.HasPrefix(rule, "CT003") {
			ruleColor = c.Green
		}

		// Extract just the message without the rule prefix
		msg := f.Message
		if idx := strings.Index(msg, ":"); idx > 0 && strings.HasPrefix(msg, "CT") {
			msg = strings.TrimSpace(msg[idx+1:])
		}

		if f.Pos != "" {
			// Format: path:line:col
			pos := f.Pos
			// Make path relative if possible
			if cwd, err := os.Getwd(); err == nil {
				if rel, err := filepath.Rel(cwd, pos); err == nil && !strings.HasPrefix(rel, "..") {
					pos = rel
				}
			}
			fmt.Printf("%s%s%s %s%s%s%s %s\n",
				c.Bold, pos, c.Reset,
				ruleColor, rule, c.Reset, c.Gray+":", c.Reset+msg)
		} else {
			fmt.Printf("%s%s%s%s %s\n",
				ruleColor, rule, c.Reset, c.Gray+":", c.Reset+msg)
		}
	}
}

func printSummary(findings []Finding, toStderr bool) {
	counts := map[string]int{}
	for _, f := range findings {
		if f.Rule == "" {
			counts["UNKNOWN"]++
		} else {
			counts[f.Rule]++
		}
	}

	var keys []string
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	total := len(findings)

	var line string
	if total == 0 {
		line = fmt.Sprintf("\n%s%s✓%s No issues found\n", c.Bold, c.Green, c.Reset)
	} else {
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
		}
		line = fmt.Sprintf("\n%s%s✗%s Found %s%d%s issue(s) (%s)\n",
			c.Bold, c.Red, c.Reset,
			c.Bold, total, c.Reset,
			strings.Join(parts, ", "))
	}

	if toStderr {
		fmt.Fprint(os.Stderr, line)
	} else {
		fmt.Print(line)
	}
}

func parseGoVetJSON(s string) ([]Finding, bool) {
	var out []Finding

	// go vet -json outputs multiple JSON objects when analyzing multiple packages:
	// # pkg1
	// { json1 }
	// # pkg2
	// { json2 }
	// We need to parse each JSON object separately.

	jsonObjects := extractJSONObjects(s)
	if len(jsonObjects) == 0 {
		return out, true
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
						Pos:     pos,
						Message: msg,
						Rule:    extractRule(msg),
					})
				}
			}
		}
	}

	return out, true
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
