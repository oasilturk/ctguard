package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"

	"golang.org/x/tools/go/analysis/unitchecker"

	"github.com/oasilturk/ctguard/internal/analyzer"
	"github.com/oasilturk/ctguard/internal/confidence"
	"github.com/oasilturk/ctguard/internal/config"
)

// Build info (set via ldflags or read from debug.BuildInfo)
var (
	version = "dev"
	commit  = "unknown"
)

const vettoolEnv = "CTGUARD_VETTOOL"

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

func main() {
	// go vet -vettool=<this binary> calls us; we switch into vettool mode via env.
	if os.Getenv(vettoolEnv) == "1" {
		unitchecker.Main(analyzer.Analyzer)
		return
	}
	os.Exit(runCLI(os.Args[1:]))
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
		configPath       string
		format           string
		rules            string
		failSet          bool
		fail             bool
		quietSet         bool
		quiet            bool
		summarySet       bool
		summary          bool
		formatSet        bool
		rulesSet         bool
		minConfidenceSet bool
		minConfidence    string
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
		trimmed := strings.TrimPrefix(arg, "-")
		trimmed = strings.TrimPrefix(trimmed, "-")
		key, value, hasValue := strings.Cut(trimmed, "=")

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
		case "config":
			if v, ok := getValue(); ok {
				configPath = v
			}
		case "format":
			formatSet = true
			if v, ok := getValue(); ok {
				format = v
			}
		case "rules":
			rulesSet = true
			if v, ok := getValue(); ok {
				rules = v
			}
		case "fail":
			failSet = true
			if hasValue {
				fail = value == "true"
			} else {
				fail = true
			}
		case "quiet":
			quietSet = true
			if hasValue {
				quiet = value == "true"
			} else {
				quiet = true
			}
		case "summary":
			summarySet = true
			if hasValue {
				summary = value == "true"
			} else {
				summary = true
			}
		case "min-confidence":
			minConfidenceSet = true
			if v, ok := getValue(); ok {
				minConfidence = v
			}
		default:
			fmt.Fprintf(os.Stderr, "%s%serror:%s unknown flag: %s\n", c.Bold, c.Red, c.Reset, arg)
			fmt.Fprintf(os.Stderr, "Run 'ctguard --help' for usage.\n")
			return 2
		}
	}

	// Load config file (if specified, or auto-search)
	cfg, err := config.LoadFrom(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s%serror:%s failed to load config: %v\n", c.Bold, c.Red, c.Reset, err)
		return 2
	}

	// Apply config defaults, CLI flags override config
	if !formatSet && cfg.Format != "" {
		format = cfg.Format
	}
	if !rulesSet && cfg.GetRules() != "" {
		rules = cfg.GetRules()
	}
	if !failSet {
		if cfg.Fail != nil {
			fail = *cfg.Fail
			failSet = true
		}
	}
	if !quietSet {
		quiet = cfg.Quiet
	}
	if !summarySet {
		if cfg.Summary != nil {
			summary = *cfg.Summary
			summarySet = true
		}
	}

	if !minConfidenceSet && cfg.MinConfidence != "" {
		minConfidence = cfg.MinConfidence
	}

	if minConfidence != "" && minConfidence != "high" && minConfidence != "low" {
		fmt.Fprintf(os.Stderr, "%s%serror:%s -min-confidence must be 'high' or 'low', got %q\n", c.Bold, c.Red, c.Reset, minConfidence)
		return 2
	}

	// Apply final defaults if still not set
	if format == "" {
		format = "plain"
	}
	if rules == "" {
		rules = "all"
	}
	if !failSet {
		fail = true
	}
	if !summarySet {
		summary = true
	}

	// Validate format
	if format != "plain" && format != "json" && format != "sarif" {
		fmt.Fprintf(os.Stderr, "%s%serror:%s -format must be 'plain', 'json', or 'sarif'\n", c.Bold, c.Red, c.Reset)
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
	allFindings := parseGoVetJSON(stderr.String())

	enabled := enabledRuleSet(rules)
	minConf := confidence.ConfidenceLow
	if minConfidence != "" {
		minConf = confidence.ParseConfidenceLevel(minConfidence)
	}
	findings := filterFindings(allFindings, enabled, minConf)

	// Apply exclude patterns from config
	findings = filterExcludedPaths(findings, cfg.Exclude)

	// "Real error" means: go vet failed AND produced no findings at all (likely build/toolchain error).
	toolErr := exitCode != 0 && len(allFindings) == 0

	// Print diagnostics (ONLY our filtered findings; never forward go vet's JSON noise)
	if !quiet {
		switch format {
		case "json":
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(findings)
		case "sarif":
			printSARIF(findings)
		default:
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

	// Summary (keep JSON/SARIF clean -> summary to stderr if format=json or sarif)
	if summary {
		printSummary(findings, format == "json" || format == "sarif")
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

func exitCodeFromErr(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return 1
}
