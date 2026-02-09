package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestConcurrentLoad tests that cache is thread-safe
func TestConcurrentLoad(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".ctguard.yaml")

	content := `format: json`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	// Clear cache
	ClearCache()

	// Spawn 100 goroutines that all try to load config at the same time
	const numGoroutines = 100
	var wg sync.WaitGroup
	results := make(chan *Config, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg, err := Load()
			if err != nil {
				errors <- err
				return
			}
			results <- cfg
		}()
	}

	wg.Wait()
	close(results)
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("goroutine failed: %v", err)
	}

	// All goroutines should get the same config pointer (cached)
	var firstConfig *Config
	count := 0
	for cfg := range results {
		count++
		if firstConfig == nil {
			firstConfig = cfg
		} else if cfg != firstConfig {
			t.Error("different config pointers - cache not working properly")
		}
	}

	if count != numGoroutines {
		t.Errorf("expected %d results, got %d", numGoroutines, count)
	}

	t.Logf("✓ All %d goroutines got the same cached config", count)
}
