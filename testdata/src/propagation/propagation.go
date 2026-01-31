package propagation

import "bytes"

// Test taint propagation through operations

//ctguard:secret secret
func taintPropagation(secret []byte, data []byte) int {
	// Direct use of secret
	if len(secret) == 0 { // want "CT001"
		return 0
	}

	// Direct comparison with secret
	_ = bytes.Equal(secret, data) // want "CT002"

	return 1
}

//ctguard:secret key
func arithmeticTaint(key int, x int) int {
	// Arithmetic operations propagate taint
	derived := key + 10
	if derived > 20 { // want "CT001"
		return 1
	}

	multiplied := key * x
	if multiplied > 100 { // want "CT001"
		return 2
	}

	return 0
}
