package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/oasilturk/ctguard/internal/confidence"
	"gopkg.in/yaml.v3"
)

var (
	cachedConfig *Config
	cacheMutex   sync.RWMutex
	cacheErr     error
)

type Config struct {
	Rules         RulesConfig       `yaml:"rules"`
	Annotations   AnnotationsConfig `yaml:"annotations,omitempty"`
	Format        string            `yaml:"format,omitempty"`
	Fail          *bool             `yaml:"fail,omitempty"`
	Quiet         bool              `yaml:"quiet,omitempty"`
	Summary       *bool             `yaml:"summary,omitempty"`
	Exclude       []string          `yaml:"exclude,omitempty"`
	MinConfidence string            `yaml:"min-confidence,omitempty"`
}

type RulesConfig struct {
	Enable   []string          `yaml:"enable,omitempty"`
	Disable  []string          `yaml:"disable,omitempty"`
	Severity map[string]string `yaml:"severity,omitempty"`
}

// For marking secrets in vendor code via config
type AnnotationsConfig struct {
	Secrets []SecretAnnotation `yaml:"secrets,omitempty"`
	Ignores []IgnoreAnnotation `yaml:"ignores,omitempty"`
}

type SecretAnnotation struct {
	Package  string   `yaml:"package"`  // supports wildcards like "github.com/vendor/**"
	Function string   `yaml:"function"` // supports wildcards like "Verify*"
	Params   []string `yaml:"params"`
}

type IgnoreAnnotation struct {
	Package  string      `yaml:"package"`  // supports wildcards like "github.com/vendor/**"
	Function string      `yaml:"function"` // supports wildcards like "Validate*"
	Rules    interface{} `yaml:"rules"`    // string "all" or []string ["CT001", "CT002"]
}

type annotationMatcher interface {
	GetPackage() string
	GetFunction() string
}

func (sa SecretAnnotation) GetPackage() string  { return sa.Package }
func (sa SecretAnnotation) GetFunction() string { return sa.Function }
func (ig IgnoreAnnotation) GetPackage() string  { return ig.Package }
func (ig IgnoreAnnotation) GetFunction() string { return ig.Function }

func matchesAnnotation(m annotationMatcher, pkgPath, funcName string) bool {
	if !matchesPattern(pkgPath, m.GetPackage()) {
		return false
	}
	if !matchesPattern(funcName, m.GetFunction()) {
		return false
	}
	return true
}

func (c *Config) GetIgnoredRules(pkgPath, funcName string) []string {
	for _, ig := range c.Annotations.Ignores {
		if matchesAnnotation(ig, pkgPath, funcName) {
			rules, err := ig.parseRules()
			if err != nil {
				// Log error but don't fail - just return nil (no ignore)
				return nil
			}
			return rules
		}
	}
	return nil
}

func (ig *IgnoreAnnotation) parseRules() ([]string, error) {
	if ig.Rules == nil {
		return nil, nil
	}
	// Handle string "all"
	if s, ok := ig.Rules.(string); ok {
		if s == "all" {
			return []string{"all"}, nil
		}
		return nil, fmt.Errorf("invalid rules value: %q", s)
	}
	// Handle slice
	if slice, ok := ig.Rules.([]interface{}); ok {
		result := make([]string, 0, len(slice))
		for i, v := range slice {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("invalid rules: element %d is not a string, got %T", i, v)
			}
			if s != "" && s != "all" && !strings.HasPrefix(s, "CT") {
				return nil, fmt.Errorf("invalid rule ID: %q (must be 'all' or start with 'CT')", s)
			}
			result = append(result, s)
		}
		return result, nil
	}
	return nil, fmt.Errorf("invalid rules type: %T", ig.Rules)
}

func Default() *Config {
	trueVal := true
	return &Config{
		Rules:         RulesConfig{Enable: []string{"all"}},
		Format:        "plain",
		Fail:          &trueVal,
		Summary:       &trueVal,
		MinConfidence: "low",
	}
}

// Searches cwd → parent dirs → home for config file. Returns defaults if not found. Cached.
func Load() (*Config, error) {
	cacheMutex.RLock()
	if cachedConfig != nil || cacheErr != nil {
		defer cacheMutex.RUnlock()
		return cachedConfig, cacheErr
	}
	cacheMutex.RUnlock()

	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	// double-check (another goroutine might've loaded it)
	if cachedConfig != nil || cacheErr != nil {
		return cachedConfig, cacheErr
	}

	cachedConfig, cacheErr = LoadFrom("")
	return cachedConfig, cacheErr
}

func ClearCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	cachedConfig = nil
	cacheErr = nil
}

func LoadFrom(path string) (*Config, error) {
	if path != "" {
		return loadFile(path)
	}

	configPath, err := findConfigFile()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Default(), nil
		}
		return nil, err
	}

	return loadFile(configPath)
}

func findConfigFile() (string, error) {
	configNames := []string{".ctguard.yaml", ".ctguard.yml", ".ctguardrc"}

	cwd, err := os.Getwd()
	if err == nil {
		dir := cwd
		for {
			for _, name := range configNames {
				path := filepath.Join(dir, name)
				if fileExists(path) {
					return path, nil
				}
			}

			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		for _, name := range configNames {
			path := filepath.Join(home, name)
			if fileExists(path) {
				return path, nil
			}
		}
	}

	return "", os.ErrNotExist
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func loadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	if cfg.Format == "" {
		cfg.Format = "plain"
	}
	if len(cfg.Rules.Enable) == 0 {
		cfg.Rules.Enable = []string{"all"}
	}
	if cfg.Fail == nil {
		trueVal := true
		cfg.Fail = &trueVal
	}
	if cfg.Summary == nil {
		trueVal := true
		cfg.Summary = &trueVal
	}

	return cfg, nil
}

func (c *Config) GetRules() string {
	if len(c.Rules.Enable) == 0 || contains(c.Rules.Enable, "all") || contains(c.Rules.Enable, "*") {
		if len(c.Rules.Disable) > 0 {
			allRules := []string{"CT001", "CT002", "CT003", "CT004", "CT005", "CT006"}
			var enabled []string
			for _, rule := range allRules {
				if !contains(c.Rules.Disable, rule) {
					enabled = append(enabled, rule)
				}
			}
			if len(enabled) == 0 {
				return "all"
			}
			return joinStrings(enabled, ",")
		}
		return "all"
	}

	var enabled []string
	for _, rule := range c.Rules.Enable {
		if !contains(c.Rules.Disable, rule) {
			enabled = append(enabled, rule)
		}
	}

	if len(enabled) == 0 {
		return "all"
	}

	return joinStrings(enabled, ",")
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func joinStrings(slice []string, sep string) string {
	if len(slice) == 0 {
		return ""
	}
	result := slice[0]
	for i := 1; i < len(slice); i++ {
		result += sep + slice[i]
	}
	return result
}

func (c *Config) GetSecretParams(pkgPath, funcName string) []string {
	for _, sa := range c.Annotations.Secrets {
		if matchesAnnotation(sa, pkgPath, funcName) {
			return sa.Params
		}
	}
	return nil
}

func (c *Config) GetMinConfidence() confidence.ConfidenceLevel {
	if c.MinConfidence == "" {
		return confidence.ConfidenceLow
	}
	return confidence.ParseConfidenceLevel(c.MinConfidence)
}

func matchesPattern(str, pattern string) bool {
	if pattern == "" {
		return false
	}

	if str == pattern {
		return true
	}

	if !contains([]string{pattern}, "*") {
		return false
	}

	if strings.Contains(pattern, "**") {
		parts := strings.Split(pattern, "/")
		for i, part := range parts {
			if part == "**" {
				prefix := ""
				if i > 0 {
					prefix = strings.Join(parts[:i], "/")
				}
				suffix := ""
				if i < len(parts)-1 {
					suffix = strings.Join(parts[i+1:], "/")
				}

				if prefix != "" && !strings.HasPrefix(str, prefix) {
					continue
				}
				if suffix != "" && !strings.HasSuffix(str, suffix) {
					continue
				}
				return true
			}
		}
	}

	matched, _ := filepath.Match(pattern, str)
	return matched
}
