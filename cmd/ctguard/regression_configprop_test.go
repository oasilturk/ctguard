package main

import (
	"os"
	"testing"
)

const configsecretTarget = "./testdata/src/configsecret/"

// secretCfg marks configsecret.CheckToken's token param secret via config only.
const secretCfg = `annotations:
  secrets:
    - package: "github.com/oasilturk/ctguard/testdata/src/configsecret"
      function: "CheckToken"
      params: ["token"]
`

// TestRegressionBugB_ConfigPropagated guards Bug B: a -config secret annotation
// must reach the vettool subprocess. The configsecret fixture has no inline
// annotation, so it only triggers CT002 once the config is propagated. A fresh
// GOCACHE per run keeps the two cases independent.
func TestRegressionBugB_ConfigPropagated(t *testing.T) {
	exe := buildTestBinary(t)
	defer func() { _ = os.Remove(exe) }()
	root := getProjectRoot(t)

	annotated := writeTempConfig(t, secretCfg)
	emptyCfg := writeTempConfig(t, "# empty\n")

	t.Run("with_config_finds_secret", func(t *testing.T) {
		env := []string{"GOCACHE=" + t.TempDir()}
		findings := runForFindings(t, exe, root, env, "-config="+annotated, configsecretTarget)
		if len(findings) == 0 {
			t.Fatalf("expected >0 findings with -config %s, got 0 (Bug B: config not propagated to vettool subprocess)", annotated)
		}
	})

	t.Run("without_config_finds_nothing", func(t *testing.T) {
		env := []string{"GOCACHE=" + t.TempDir()}
		findings := runForFindings(t, exe, root, env, "-config="+emptyCfg, configsecretTarget)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings without the secret annotation, got %d: %+v", len(findings), findings)
		}
	})
}

// TestRegressionConfigHashBustsCache guards the cache-busting fix: editing a
// config at a fixed path must change results even when go vet's result cache is
// warm (Go 1.26 caches vettool runs, which otherwise go stale). The CLI folds the
// config content hash into the vet cache key. Both runs share one GOCACHE.
func TestRegressionConfigHashBustsCache(t *testing.T) {
	exe := buildTestBinary(t)
	defer func() { _ = os.Remove(exe) }()
	root := getProjectRoot(t)

	cfg := writeTempConfig(t, secretCfg)
	shared := []string{"GOCACHE=" + t.TempDir()}

	if findings := runForFindings(t, exe, root, shared, "-config="+cfg, configsecretTarget); len(findings) == 0 {
		t.Fatalf("expected >0 findings with the secret annotation, got 0")
	}

	if err := os.WriteFile(cfg, []byte("# empty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if findings := runForFindings(t, exe, root, shared, "-config="+cfg, configsecretTarget); len(findings) != 0 {
		t.Fatalf("expected 0 findings after emptying config (stale cache not busted), got %d: %+v", len(findings), findings)
	}
}
