package clean

import "crypto/subtle"

// Test cases that should NOT produce any warnings

// No annotation - not a secret
func publicCompare(a, b []byte) bool {
	return string(a) == string(b) // OK - no secret annotation
}

// Using constant-time comparison - safe
//
//ctguard:secret key
func safeCompare(key []byte, data []byte) int {
	return subtle.ConstantTimeCompare(key, data) // OK - constant-time
}

// Branching on non-secret data only
//
//ctguard:secret token
func safeBranching(token []byte, length int) []byte {
	// Branch on non-secret parameter
	if length <= 0 {
		return nil
	}

	// Just copy without branching on secret
	result := make([]byte, len(token))
	copy(result, token)
	return result
}

// Multiple secrets, but used safely
//
//ctguard:secret a b
func multipleSecretsSafe(a, b []byte) int {
	return subtle.ConstantTimeCompare(a, b) // OK - constant-time
}
