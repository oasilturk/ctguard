package lengthcontent

// Length vs content taint: len()/cap() of a secret slice is metadata and not
// flagged, while content access (secretSlice[i], bytes.Equal) still is. A
// secret-sized make() taints the result's length, so len() of it does fire.

import "bytes"

//ctguard:secret secret
func lenIsMetadata(secret []byte) int {
	if len(secret) == 0 {
		return 0
	}
	if len(secret) > 16 {
		return 1
	}
	return 2
}

//ctguard:secret secret
func capIsMetadata(secret []byte) int {
	if cap(secret) > 32 {
		return 1
	}
	return 0
}

//ctguard:secret secret
func contentTriggers(secret []byte) int {
	if secret[0] == 0 { // want "CT001"
		return 1
	}
	_ = bytes.Equal(secret, []byte{1, 2, 3}) // want "CT002"
	return 0
}

// Secret-derived size taints the length, so len() of the result fires.
//
//ctguard:secret n
func makeWithSecretSize(n int) int {
	buf := make([]byte, n)
	if len(buf) > 0 { // want "CT001"
		return 1
	}
	return 0
}

// Clean size with secret content: length stays clean.
//
//ctguard:secret secret
func makeWithCleanSize(secret byte) int {
	buf := make([]byte, 16)
	buf[0] = secret
	if len(buf) == 16 {
		return 1
	}
	return 0
}
