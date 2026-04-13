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
			expected: "CT001,CT002,CT004,CT005,CT006,CT007",
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
	if !matchesAnnotation(sa1, "github.com/vendor/crypto", "VerifyMAC") {
		t.Error("expected match for exact package and function")
	}
	if matchesAnnotation(sa1, "github.com/other/crypto", "VerifyMAC") {
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

func TestIsolatedAnnotationConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".ctguard.yaml")

	content := "annotations:\n  isolated:\n    - package: \"github.com/vendor/crypto\"\n      function: \"CriticalVerify\"\n    - package: \"github.com/myapp/**\"\n      function: \"Secure*\"\n"

	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFrom(configPath)
	if err != nil {
		t.Fatalf("LoadFrom failed: %v", err)
	}

	if len(cfg.Annotations.Isolated) != 2 {
		t.Errorf("expected 2 isolated annotations, got %d", len(cfg.Annotations.Isolated))
	}

	ia1 := cfg.Annotations.Isolated[0]
	if ia1.Package != "github.com/vendor/crypto" {
		t.Errorf("expected package 'github.com/vendor/crypto', got %q", ia1.Package)
	}
	if ia1.Function != "CriticalVerify" {
		t.Errorf("expected function 'CriticalVerify', got %q", ia1.Function)
	}
}

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		str     string
		pattern string
		want    bool
	}{
		// exact match
		{"github.com/foo/bar", "github.com/foo/bar", true},
		{"github.com/foo/bar", "github.com/other", false},
		// empty pattern
		{"anything", "", false},
		// simple wildcard
		{"VerifyMAC", "Verify*", true},
		{"VerifyMAC", "*MAC", true},
		{"Other", "Verify*", false},
		// double-star glob
		{"github.com/myapp/internal/crypto", "github.com/myapp/**", true},
		{"github.com/other/pkg", "github.com/myapp/**", false},
		// double-star in middle
		{"github.com/foo/bar/baz", "github.com/**/baz", true},
		{"github.com/foo/bar/qux", "github.com/**/baz", false},
		// no wildcard, no match
		{"foo", "bar", false},
	}
	for _, tt := range tests {
		t.Run(tt.str+"_"+tt.pattern, func(t *testing.T) {
			if got := matchesPattern(tt.str, tt.pattern); got != tt.want {
				t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.str, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestGetMinConfidence(t *testing.T) {
	tests := []struct {
		name string
		conf string
		want string
	}{
		{"empty defaults to low", "", "low"},
		{"high", "high", "high"},
		{"low", "low", "low"},
		{"unknown defaults to low", "bogus", "low"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{MinConfidence: tt.conf}
			if got := cfg.GetMinConfidence().String(); got != tt.want {
				t.Errorf("GetMinConfidence() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetIgnoredRules(t *testing.T) {
	cfg := &Config{
		Annotations: AnnotationsConfig{
			Ignores: []IgnoreAnnotation{
				{Package: "github.com/foo", Function: "Bar", Rules: "all"},
				{Package: "github.com/baz", Function: "Qux", Rules: []interface{}{"CT001", "CT002"}},
			},
		},
	}

	t.Run("all rules", func(t *testing.T) {
		got := cfg.GetIgnoredRules("github.com/foo", "Bar")
		if len(got) != 1 || got[0] != "all" {
			t.Errorf("expected [all], got %v", got)
		}
	})

	t.Run("specific rules", func(t *testing.T) {
		got := cfg.GetIgnoredRules("github.com/baz", "Qux")
		if len(got) != 2 {
			t.Errorf("expected 2 rules, got %v", got)
		}
	})

	t.Run("no match", func(t *testing.T) {
		got := cfg.GetIgnoredRules("github.com/other", "Func")
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

func TestParseRules(t *testing.T) {
	t.Run("nil rules", func(t *testing.T) {
		ig := &IgnoreAnnotation{Rules: nil}
		got, err := ig.parseRules()
		if err != nil || got != nil {
			t.Errorf("expected nil/nil, got %v/%v", got, err)
		}
	})

	t.Run("string all", func(t *testing.T) {
		ig := &IgnoreAnnotation{Rules: "all"}
		got, err := ig.parseRules()
		if err != nil || len(got) != 1 || got[0] != "all" {
			t.Errorf("expected [all], got %v (err: %v)", got, err)
		}
	})

	t.Run("invalid string", func(t *testing.T) {
		ig := &IgnoreAnnotation{Rules: "bogus"}
		_, err := ig.parseRules()
		if err == nil {
			t.Error("expected error for invalid string")
		}
	})

	t.Run("slice of rules", func(t *testing.T) {
		ig := &IgnoreAnnotation{Rules: []interface{}{"CT001", "CT003"}}
		got, err := ig.parseRules()
		if err != nil || len(got) != 2 {
			t.Errorf("expected 2 rules, got %v (err: %v)", got, err)
		}
	})

	t.Run("slice with non-string", func(t *testing.T) {
		ig := &IgnoreAnnotation{Rules: []interface{}{"CT001", 42}}
		_, err := ig.parseRules()
		if err == nil {
			t.Error("expected error for non-string element")
		}
	})

	t.Run("slice with invalid rule ID", func(t *testing.T) {
		ig := &IgnoreAnnotation{Rules: []interface{}{"INVALID"}}
		_, err := ig.parseRules()
		if err == nil {
			t.Error("expected error for invalid rule ID")
		}
	})

	t.Run("invalid type", func(t *testing.T) {
		ig := &IgnoreAnnotation{Rules: 42}
		_, err := ig.parseRules()
		if err == nil {
			t.Error("expected error for invalid type")
		}
	})
}

func TestGetSecretParams(t *testing.T) {
	cfg := &Config{
		Annotations: AnnotationsConfig{
			Secrets: []SecretAnnotation{
				{Package: "github.com/foo", Function: "Verify", Params: []string{"key", "mac"}},
			},
		},
	}

	t.Run("match", func(t *testing.T) {
		got := cfg.GetSecretParams("github.com/foo", "Verify")
		if len(got) != 2 {
			t.Errorf("expected 2 params, got %v", got)
		}
	})

	t.Run("no match", func(t *testing.T) {
		got := cfg.GetSecretParams("github.com/other", "Func")
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

func TestGetRulesDisableAll(t *testing.T) {
	cfg := &Config{
		Rules: RulesConfig{
			Enable:  []string{"all"},
			Disable: []string{"CT001", "CT002", "CT003", "CT004", "CT005", "CT006", "CT007"},
		},
	}
	if got := cfg.GetRules(); got != "all" {
		t.Errorf("expected 'all' fallback when all disabled, got %q", got)
	}
}

func TestGetRulesEnableWithDisable(t *testing.T) {
	cfg := &Config{
		Rules: RulesConfig{
			Enable:  []string{"CT001", "CT002", "CT003"},
			Disable: []string{"CT002"},
		},
	}
	if got := cfg.GetRules(); got != "CT001,CT003" {
		t.Errorf("expected 'CT001,CT003', got %q", got)
	}
}

func TestGetRulesAllDisabled(t *testing.T) {
	cfg := &Config{
		Rules: RulesConfig{
			Enable:  []string{"CT001"},
			Disable: []string{"CT001"},
		},
	}
	if got := cfg.GetRules(); got != "all" {
		t.Errorf("expected 'all' fallback, got %q", got)
	}
}

func TestGetIsolatedFunctions(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *Config
		pkgPath  string
		funcName string
		want     bool
	}{
		{
			name: "exact match",
			cfg: &Config{
				Annotations: AnnotationsConfig{
					Isolated: []IsolatedAnnotation{
						{Package: "github.com/vendor/crypto", Function: "CriticalVerify"},
					},
				},
			},
			pkgPath:  "github.com/vendor/crypto",
			funcName: "CriticalVerify",
			want:     true,
		},
		{
			name: "no match - different function",
			cfg: &Config{
				Annotations: AnnotationsConfig{
					Isolated: []IsolatedAnnotation{
						{Package: "github.com/vendor/crypto", Function: "CriticalVerify"},
					},
				},
			},
			pkgPath:  "github.com/vendor/crypto",
			funcName: "OtherFunc",
			want:     false,
		},
		{
			name: "no match - different package",
			cfg: &Config{
				Annotations: AnnotationsConfig{
					Isolated: []IsolatedAnnotation{
						{Package: "github.com/vendor/crypto", Function: "CriticalVerify"},
					},
				},
			},
			pkgPath:  "github.com/other/pkg",
			funcName: "CriticalVerify",
			want:     false,
		},
		{
			name: "empty isolated list",
			cfg: &Config{
				Annotations: AnnotationsConfig{},
			},
			pkgPath:  "github.com/vendor/crypto",
			funcName: "CriticalVerify",
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.GetIsolatedFunctions(tc.pkgPath, tc.funcName)
			if got != tc.want {
				t.Errorf("GetIsolatedFunctions(%q, %q) = %v, want %v",
					tc.pkgPath, tc.funcName, got, tc.want)
			}
		})
	}
}
