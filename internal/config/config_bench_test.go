package config

import (
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkLoadWithoutCache measures performance without caching
func BenchmarkLoadWithoutCache(b *testing.B) {
	tmpDir := b.TempDir()
	configPath := filepath.Join(tmpDir, ".ctguard.yaml")

	content := `
rules:
  enable: [all]
annotations:
  secrets:
    - package: "github.com/vendor/crypto"
      function: "VerifyMAC"
      params: ["mac", "key"]
format: json
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		b.Fatal(err)
	}

	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	if err := os.Chdir(tmpDir); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ClearCache() // Simulate no cache
		_, _ = Load()
	}
}

// BenchmarkLoadWithCache measures performance with caching
func BenchmarkLoadWithCache(b *testing.B) {
	tmpDir := b.TempDir()
	configPath := filepath.Join(tmpDir, ".ctguard.yaml")

	content := `
rules:
  enable: [all]
annotations:
  secrets:
    - package: "github.com/vendor/crypto"
      function: "VerifyMAC"
      params: ["mac", "key"]
format: json
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		b.Fatal(err)
	}

	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	if err := os.Chdir(tmpDir); err != nil {
		b.Fatal(err)
	}

	// Pre-load cache
	ClearCache()
	_, _ = Load()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Load() // Should hit cache
	}
}

// BenchmarkCollectSecretsWithCache measures real-world usage
func BenchmarkCollectSecretsWithCache(b *testing.B) {
	tmpDir := b.TempDir()
	configPath := filepath.Join(tmpDir, ".ctguard.yaml")

	content := `
annotations:
  secrets:
    - package: "github.com/vendor/crypto"
      function: "VerifyMAC"
      params: ["mac", "key"]
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		b.Fatal(err)
	}

	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	if err := os.Chdir(tmpDir); err != nil {
		b.Fatal(err)
	}

	// Pre-load cache
	ClearCache()
	_, _ = Load()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate multiple packages calling Load()
		for j := 0; j < 100; j++ {
			_, _ = Load()
		}
	}
}
