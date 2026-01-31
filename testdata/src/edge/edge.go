package edge

import (
	"bytes"
	"strings"
)

// Edge cases and special scenarios

// Empty function body
//
//ctguard:secret x
func emptyBody(x int) {
}

// Multiple comparisons in same function - triggers both CT001 and CT002
//
//ctguard:secret key
func multipleComparisons(key []byte, a, b, c []byte) bool {
	r1 := bytes.Equal(key, a) // want "CT001" "CT002"
	r2 := bytes.Equal(key, b) // want "CT001" "CT002"
	r3 := bytes.Equal(key, c) // want "CT002"
	return r1 && r2 && r3
}

// String operations - triggers both CT001 and CT002
//
//ctguard:secret password
func stringOps(password string, stored string) bool {
	// Direct comparison in if - triggers both
	if password == stored { // want "CT001" "CT002"
		return true
	}

	// strings.Compare in if - triggers both
	if strings.Compare(password, stored) == 0 { // want "CT001" "CT002"
		return true
	}

	return false
}

// Switch statement on secret - each case is a branch
//
//ctguard:secret mode
func switchOnSecret(mode int) string {
	switch mode {
	case 1: // want "CT001"
		return "one"
	case 2: // want "CT001"
		return "two"
	default:
		return "other"
	}
}
