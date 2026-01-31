package comparisons

import (
	"bytes"
	"crypto/subtle"
)

// CT002: Non-constant-time comparison tests

//ctguard:secret key
func unsafeCompare(key []byte, data []byte) int {
	_ = bytes.Equal(key, data) // want "CT002"
	_ = subtle.ConstantTimeCompare(key, data)
	return 0
}

//ctguard:secret password
func stringCompare(password string, stored string, extra int) int {
	_ = (password == stored) // want "CT002"
	return 0
}
