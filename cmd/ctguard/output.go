package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func printHelp() {
	fmt.Printf(`%s%sCTGuard%s - Detect timing side-channel vulnerabilities in Go code

%sUSAGE%s
    ctguard [flags] [packages...]

%sEXAMPLES%s
    ctguard ./...                      %s# Scan entire project%s
    ctguard -rules=CT001 ./...         %s# Only check for secret-dependent branches%s
    ctguard -format=json ./...         %s# JSON output for CI integration%s
    ctguard -format=sarif ./...        %s# SARIF output for GitHub Code Scanning%s
    ctguard -fail=false ./...          %s# Don't fail on findings (for reports)%s

%sFLAGS%s
    -format string    Output format: plain, json, or sarif (default "plain")
    -rules string     Comma-separated rule IDs or 'all' (default "all")
    -fail             Exit with code 1 if findings exist (default true)
    -quiet            Suppress diagnostic output
    -summary          Print summary after diagnostics (default true)
    -min-confidence   Minimum confidence level to report: high or low (default "low")
    -config string    Path to config file (default: auto-search for .ctguard.yaml)
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

    %sCT004%s  Secret data exposure
           Detects when secret data is passed to logging, printing,
           or error formatting functions (fmt.Print*, log.*, fmt.Errorf).
           Secrets may be exposed in logs, console output, or error messages.

    %sCT005%s  Variable-time arithmetic operations
           Detects use of division (/), modulo (%%), shifts (<<, >>), and
           variable-time library functions (math.Mod, math/big) with secret
           data. Use bit masking or crypto/subtle for constant-time operations.

    %sCT006%s  Channel operations with secret data
           Detects when secret data is sent to or received from channels.
           Channel communication can leak timing information and create attack
           surfaces where goroutines can observe secret data.

    %sCT007%s  Secret-tainted data in I/O sinks within isolated regions
           Detects when secret-tainted values flow into network, file, or
           syscall I/O functions inside //ctguard:isolated regions.

%sANNOTATIONS%s
    Mark function parameters as secret:

        //ctguard:secret key
        func Verify(key []byte, data []byte) bool { ... }

    Suppress specific findings:

        //ctguard:ignore CT002 -- using constant-time internally
        func SafeCompare(a, b []byte) bool { ... }

        func Process(key []byte) {
            _ = bytes.Equal(key, x) //ctguard:ignore CT002
        }

    Ignore formats:
        //ctguard:ignore              Ignore all rules
        //ctguard:ignore CT001        Ignore specific rule
        //ctguard:ignore CT001 CT002  Ignore multiple rules
        //ctguard:ignore CT001 -- reason   With explanation

    Mark regions as isolated, function-level or block-level:

        //ctguard:isolated
        func IsolatedRegion() {
            // This region is isolated from secret data
        }

        //ctguard:isolated begin
        ...
        some code going on here
        ...
        //ctguard:isolated end

%sCONFIGURATION%s
    CTGuard searches for a .ctguard.yaml file in:
    - Current directory (and parent directories)
    - Home directory

    Example .ctguard.yaml:
        rules:
          enable: [CT001, CT002, CT005, CT006]  # or 'all'
          disable: [CT003, CT004]
          severity:
            CT001: warning
            CT002: error
        format: json
        fail: false
        exclude:
          - testdata/**
          - vendor/**

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
		c.Gray, c.Reset,
		c.Bold, c.Reset,
		c.Bold, c.Reset,
		c.Yellow, c.Reset,
		c.Yellow, c.Reset,
		c.Yellow, c.Reset,
		c.Yellow, c.Reset,
		c.Yellow, c.Reset,
		c.Yellow, c.Reset,
		c.Yellow, c.Reset,
		c.Bold, c.Reset,
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

func printPlain(findings []Finding) {
	for _, f := range findings {
		rule := f.Rule
		if rule == "" {
			rule = "???"
		}

		ruleColor := c.Yellow
		switch rule {
		case "CT001":
			ruleColor = c.Magenta
		case "CT002":
			ruleColor = c.Cyan
		case "CT003":
			ruleColor = c.Green
		case "CT004":
			ruleColor = c.Red
		case "CT005":
			ruleColor = c.Blue
		case "CT007":
			ruleColor = c.Orange
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

func printSARIF(findings []Finding) {
	// Define rules metadata
	rules := []SarifRule{
		{
			ID:               "CT001",
			Name:             "SecretDependentBranch",
			ShortDescription: SarifMessage{Text: "Secret-dependent branch"},
			FullDescription:  SarifMessage{Text: "Detects control flow that depends on secret data, which can leak information through timing differences."},
			HelpURI:          "https://github.com/oasilturk/ctguard#ct001",
			DefaultConfig:    SarifDefaultConfig{Level: "error"},
		},
		{
			ID:               "CT002",
			Name:             "NonConstantTimeComparison",
			ShortDescription: SarifMessage{Text: "Non-constant-time comparison"},
			FullDescription:  SarifMessage{Text: "Detects use of variable-time comparison operations (bytes.Equal, strings.Compare, ==) with secret data. Use crypto/subtle for constant-time comparisons."},
			HelpURI:          "https://github.com/oasilturk/ctguard#ct002",
			DefaultConfig:    SarifDefaultConfig{Level: "error"},
		},
		{
			ID:               "CT003",
			Name:             "SecretDependentIndexing",
			ShortDescription: SarifMessage{Text: "Secret-dependent indexing"},
			FullDescription:  SarifMessage{Text: "Detects array, slice, and map indexing where the index depends on secret data. This can leak information through cache-timing side-channels."},
			HelpURI:          "https://github.com/oasilturk/ctguard#ct003",
			DefaultConfig:    SarifDefaultConfig{Level: "error"},
		},
		{
			ID:               "CT004",
			Name:             "SecretDataExposure",
			ShortDescription: SarifMessage{Text: "Secret data exposure"},
			FullDescription:  SarifMessage{Text: "Detects when secret data is passed to logging, printing, or error formatting functions. Secrets may be exposed in logs, console output, or error messages."},
			HelpURI:          "https://github.com/oasilturk/ctguard#ct004",
			DefaultConfig:    SarifDefaultConfig{Level: "error"},
		},
		{
			ID:               "CT005",
			Name:             "VariableTimeArithmetic",
			ShortDescription: SarifMessage{Text: "Variable-time arithmetic"},
			FullDescription:  SarifMessage{Text: "Detects use of variable-time arithmetic operations (/, %, <<, >>) with secret data. Use crypto/subtle for constant-time arithmetic."},
			HelpURI:          "https://github.com/oasilturk/ctguard#ct005",
			DefaultConfig:    SarifDefaultConfig{Level: "error"},
		},
		{
			ID:               "CT006",
			Name:             "ChannelOperationsWithSecretData",
			ShortDescription: SarifMessage{Text: "Channel operations with secret data"},
			FullDescription:  SarifMessage{Text: "Detects when secret data is sent to or received from channels. Channel communication can leak timing information and create attack surfaces where goroutines can observe secret data."},
			HelpURI:          "https://github.com/oasilturk/ctguard#ct006",
			DefaultConfig:    SarifDefaultConfig{Level: "error"},
		},
		{
			ID:               "CT007",
			Name:             "SecretDataInIOSink",
			ShortDescription: SarifMessage{Text: "Secret data in I/O sink within isolated region"},
			FullDescription:  SarifMessage{Text: "Detects when secret-tainted values flow into network, file, or syscall I/O functions inside //ctguard:isolated regions. Isolated regions are code sections that must not leak secrets through I/O operations."},
			HelpURI:          "https://github.com/oasilturk/ctguard#ct007",
			DefaultConfig:    SarifDefaultConfig{Level: "error"},
		},
	}

	// Convert findings to SARIF results (must be empty array, not null)
	results := make([]SarifResult, 0)
	for _, f := range findings {
		// Extract message without rule prefix
		msg := f.Message
		if idx := strings.Index(msg, ":"); idx > 0 && strings.HasPrefix(msg, "CT") {
			msg = strings.TrimSpace(msg[idx+1:])
		}

		result := SarifResult{
			RuleID:  f.Rule,
			Level:   "error",
			Message: SarifMessage{Text: msg},
		}

		// Parse position (file:line:col)
		// Use LastIndex to handle Windows paths like C:\file.go:10:5
		if f.Pos != "" {
			filePath := f.Pos
			var lineStr, colStr string

			if idx := strings.LastIndex(f.Pos, ":"); idx > 0 {
				candidate := f.Pos[idx+1:]
				if len(candidate) > 0 && candidate[0] >= '0' && candidate[0] <= '9' {
					rest := f.Pos[:idx]
					colStr = candidate
					if idx2 := strings.LastIndex(rest, ":"); idx2 > 0 {
						candidate2 := rest[idx2+1:]
						if len(candidate2) > 0 && candidate2[0] >= '0' && candidate2[0] <= '9' {
							filePath = rest[:idx2]
							lineStr = candidate2
							colStr = candidate
						} else {
							filePath = rest
							lineStr = colStr
							colStr = ""
						}
					} else {
						filePath = rest
						lineStr = colStr
						colStr = ""
					}
				}
			}

			loc := SarifLocation{
				PhysicalLocation: SarifPhysicalLocation{
					ArtifactLocation: SarifArtifactLocation{
						URI:       filePath,
						URIBaseID: "%SRCROOT%",
					},
				},
			}

			line := 0
			if lineStr != "" {
				_, _ = fmt.Sscanf(lineStr, "%d", &line)
			}
			if line > 0 {
				loc.PhysicalLocation.Region = &SarifRegion{StartLine: line}
				col := 0
				if colStr != "" {
					_, _ = fmt.Sscanf(colStr, "%d", &col)
				}
				if col > 0 {
					loc.PhysicalLocation.Region.StartColumn = col
				}
			}

			result.Locations = []SarifLocation{loc}
		}

		results = append(results, result)
	}

	report := SarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "ctguard",
						Version:        version,
						InformationURI: "https://github.com/oasilturk/ctguard",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)
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
