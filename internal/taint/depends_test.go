package taint

import (
	"testing"
)

func TestNewDepender(t *testing.T) {
	secrets := map[string]bool{"key": true, "token": true}
	d := NewDepender(secrets)

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

func TestDepender_DependsNil(t *testing.T) {
	d := NewDepender(map[string]bool{"key": true})

	// nil value should return false
	if d.Depends(nil) {
		t.Error("Depends(nil) should return false")
	}
}

func TestNewDepender_EmptySecrets(t *testing.T) {
	d := NewDepender(map[string]bool{})

	if len(d.secretParams) != 0 {
		t.Errorf("expected empty secretParams, got %v", d.secretParams)
	}
}

func TestNewDepender_NilSecrets(t *testing.T) {
	d := NewDepender(nil)

	if d.Depends(nil) {
		t.Error("Depends should return false for nil value")
	}
}

// Note: Full SSA-based testing is done via analysistest in the analyzer package.
// These tests cover the basic API contract and edge cases.
