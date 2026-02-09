package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	if cfg.Format != "plain" {
		t.Errorf("expected format 'plain', got %q", cfg.Format)
	}

	if cfg.Fail == nil || !*cfg.Fail {
		t.Error("expected fail to be true by default")
	}

	if cfg.Summary == nil || !*cfg.Summary {
		t.Error("expected summary to be true by default")
	}

	if len(cfg.Rules.Enable) != 1 || cfg.Rules.Enable[0] != "all" {
		t.Errorf("expected rules.enable to be ['all'], got %v", cfg.Rules.Enable)
	}
}

func TestLoadFrom(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".ctguard.yaml")

	content := `
format: json
fail: false
quiet: true
rules:
  enable:
    - CT001
    - CT002
  disable:
    - CT003
  severity:
    CT001: warning
    CT002: error
exclude:
  - "testdata/**"
  - "vendor/**"
`

	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFrom(configPath)
	if err != nil {
		t.Fatalf("LoadFrom failed: %v", err)
	}

	if cfg.Format != "json" {
		t.Errorf("expected format 'json', got %q", cfg.Format)
	}

	if cfg.Fail == nil || *cfg.Fail {
		t.Error("expected fail to be false")
	}

	if !cfg.Quiet {
		t.Error("expected quiet to be true")
	}

	if len(cfg.Rules.Enable) != 2 {
		t.Errorf("expected 2 enabled rules, got %d", len(cfg.Rules.Enable))
	}

	if len(cfg.Rules.Disable) != 1 || cfg.Rules.Disable[0] != "CT003" {
		t.Errorf("expected CT003 to be disabled, got %v", cfg.Rules.Disable)
	}

	if cfg.Rules.Severity["CT001"] != "warning" {
		t.Errorf("expected CT001 severity 'warning', got %q", cfg.Rules.Severity["CT001"])
	}

	if len(cfg.Exclude) != 2 {
		t.Errorf("expected 2 exclude patterns, got %d", len(cfg.Exclude))
	}
}

func TestIsRuleEnabled(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		ruleID   string
		expected bool
	}{
		{
			name:     "default config enables all",
			config:   Default(),
			ruleID:   "CT001",
			expected: true,
		},
		{
			name: "explicitly enabled",
			config: &Config{
				Rules: RulesConfig{
					Enable: []string{"CT001", "CT002"},
				},
			},
			ruleID:   "CT001",
			expected: true,
		},
		{
			name: "not in enable list",
			config: &Config{
				Rules: RulesConfig{
					Enable: []string{"CT001"},
				},
			},
			ruleID:   "CT002",
			expected: false,
		},
		{
			name: "explicitly disabled",
			config: &Config{
				Rules: RulesConfig{
					Enable:  []string{"all"},
					Disable: []string{"CT001"},
				},
			},
			ruleID:   "CT001",
			expected: false,
		},
		{
			name: "all with one disabled",
			config: &Config{
				Rules: RulesConfig{
					Enable:  []string{"all"},
					Disable: []string{"CT003"},
				},
			},
			ruleID:   "CT001",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsRuleEnabled(tt.ruleID)
			if result != tt.expected {
				t.Errorf("IsRuleEnabled(%q) = %v, expected %v", tt.ruleID, result, tt.expected)
			}
		})
	}
}

func TestGetRules(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name:     "default returns all",
			config:   Default(),
			expected: "all",
		},
		{
			name: "specific rules",
			config: &Config{
				Rules: RulesConfig{
					Enable: []string{"CT001", "CT002"},
				},
			},
			expected: "CT001,CT002",
		},
		{
			name: "all with disabled filtered",
			config: &Config{
				Rules: RulesConfig{
					Enable:  []string{"all"},
					Disable: []string{"CT003"},
				},
			},
			expected: "CT001,CT002,CT004", // Returns explicit list when using all+disable
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetRules()
			if result != tt.expected {
				t.Errorf("GetRules() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestFindConfigFile(t *testing.T) {
	// Create a temporary directory structure
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create config in parent
	configPath := filepath.Join(tmpDir, ".ctguard.yaml")
	if err := os.WriteFile(configPath, []byte("format: json\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Change to subdir
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chdir(oldWd)
	}()

	if err := os.Chdir(subDir); err != nil {
		t.Fatal(err)
	}

	// Should find config in parent
	found, err := findConfigFile()
	if err != nil {
		t.Fatalf("findConfigFile failed: %v", err)
	}

	// Resolve both paths to handle symlinks (e.g., /var -> /private/var on macOS)
	expectedPath, _ := filepath.EvalSymlinks(configPath)
	foundPath, _ := filepath.EvalSymlinks(found)

	if foundPath != expectedPath {
		t.Errorf("expected to find %q, got %q", expectedPath, foundPath)
	}
}

func TestLoadNonExistentFile(t *testing.T) {
	_, err := LoadFrom("/nonexistent/path/.ctguard.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".ctguard.yaml")

	// Invalid YAML
	if err := os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFrom(configPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestAnnotationsConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".ctguard.yaml")

	content := `
annotations:
  secrets:
    - package: "github.com/vendor/crypto"
      function: "VerifyMAC"
      params: ["mac", "key"]
    - package: "github.com/myapp/**"
      function: "*Secret*"
      params: ["token"]
`

	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFrom(configPath)
	if err != nil {
		t.Fatalf("LoadFrom failed: %v", err)
	}

	if len(cfg.Annotations.Secrets) != 2 {
		t.Errorf("expected 2 secret annotations, got %d", len(cfg.Annotations.Secrets))
	}

	// Test first annotation
	sa1 := cfg.Annotations.Secrets[0]
	if sa1.Package != "github.com/vendor/crypto" {
		t.Errorf("expected package 'github.com/vendor/crypto', got %q", sa1.Package)
	}
	if sa1.Function != "VerifyMAC" {
		t.Errorf("expected function 'VerifyMAC', got %q", sa1.Function)
	}
	if len(sa1.Params) != 2 {
		t.Errorf("expected 2 params, got %d", len(sa1.Params))
	}

	// Test matching
	if !sa1.MatchesFunction("github.com/vendor/crypto", "VerifyMAC") {
		t.Error("expected match for exact package and function")
	}
	if sa1.MatchesFunction("github.com/other/crypto", "VerifyMAC") {
		t.Error("expected no match for different package")
	}
}

func TestConfigCaching(t *testing.T) {
	// Clear cache before test
	ClearCache()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".ctguard.yaml")

	content := `format: json`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Change to tmpDir so Load() finds the config
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	// First load
	cfg1, err1 := Load()
	if err1 != nil {
		t.Fatalf("first Load failed: %v", err1)
	}

	// Second load should return cached config
	cfg2, err2 := Load()
	if err2 != nil {
		t.Fatalf("second Load failed: %v", err2)
	}

	// Should be the same pointer (cached)
	if cfg1 != cfg2 {
		t.Error("expected cached config to be the same pointer")
	}

	// Clear cache
	ClearCache()

	// Third load should re-load
	cfg3, err3 := Load()
	if err3 != nil {
		t.Fatalf("third Load failed: %v", err3)
	}

	// Should be different pointer after cache clear
	if cfg1 == cfg3 {
		t.Error("expected new config after cache clear")
	}
}
