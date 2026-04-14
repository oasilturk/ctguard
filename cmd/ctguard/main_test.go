package main

import (
	"os/exec"
	"testing"
)

func TestExitCodeFromErr(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if got := exitCodeFromErr(nil); got != 0 {
			t.Errorf("expected 0, got %d", got)
		}
	})

	t.Run("exit_error", func(t *testing.T) {
		// Create a real ExitError by running a command that fails
		cmd := exec.Command("sh", "-c", "exit 42")
		err := cmd.Run()
		if got := exitCodeFromErr(err); got != 42 {
			t.Errorf("expected 42, got %d", got)
		}
	})

	t.Run("other_error", func(t *testing.T) {
		err := exec.Command("nonexistent-binary-12345").Run()
		if got := exitCodeFromErr(err); got != 1 {
			t.Errorf("expected 1 for non-ExitError, got %d", got)
		}
	})
}
