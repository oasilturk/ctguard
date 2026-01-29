package b

import (
	"bytes"
	"crypto/subtle"
)

//ctguard:secret k
func f(k []byte, x []byte) int {
	_ = bytes.Equal(k, x) // want "CT002"
	_ = subtle.ConstantTimeCompare(k, x)
	return 0
}

//ctguard:secret s i
func g(s string, t string, i int) int {
	_ = (s == t) // want "CT002"
	return 0
}
