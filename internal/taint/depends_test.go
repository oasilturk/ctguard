package taint

import (
	"testing"
)

func TestNewDepender(t *testing.T) {
	secrets := map[string]bool{"key": true, "token": true}
	d := NewDepender(nil, secrets, nil) // nil function and ipAnalyzer ok for basic tests

	if d.secretParams == nil {
		t.Error("secretParams should not be nil")
	}

	if d.memo == nil {
		t.Error("memo should not be nil")
	}

	if d.inStack == nil {
		t.Error("inStack should not be nil")
	}

	if !d.secretParams["key"] {
		t.Error("expected 'key' to be in secretParams")
	}

	if !d.secretParams["token"] {
		t.Error("expected 'token' to be in secretParams")
	}

	if d.secretParams["other"] {
		t.Error("expected 'other' to not be in secretParams")
	}
}

func TestDepender_DependsOnNil(t *testing.T) {
	d := NewDepender(nil, map[string]bool{"key": true}, nil)

	// nil value should return empty secret
	if secret, _ := d.DependsOn(nil); secret != "" {
		t.Errorf("DependsOn(nil) should return empty secret, got %q", secret)
	}
}

func TestNewDepender_EmptySecrets(t *testing.T) {
	d := NewDepender(nil, map[string]bool{}, nil)

	if len(d.secretParams) != 0 {
		t.Errorf("expected empty secretParams, got %v", d.secretParams)
	}
}

func TestNewDepender_NilSecrets(t *testing.T) {
	d := NewDepender(nil, nil, nil)

	if secret, _ := d.DependsOn(nil); secret != "" {
		t.Errorf("DependsOn(nil) should return empty secret, got %q", secret)
	}
}

// Note: Full SSA-based testing is done via analysistest in the analyzer package.
// These tests cover the basic API contract and edge cases.
