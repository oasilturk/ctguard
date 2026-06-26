package constanttime

import (
	"crypto/hmac"
	"crypto/subtle"
)

func grant() {}

// Constant-time comparison branches must not be flagged (no "want" = no diagnostic).

//ctguard:secret password
func CompareBranch(password, stored []byte) {
	if subtle.ConstantTimeCompare(password, stored) == 1 {
		grant()
	}
}

//ctguard:secret apiKey
func HmacBranch(apiKey, expected []byte) {
	if hmac.Equal(apiKey, expected) {
		grant()
	}
}

// Control: a plain secret branch still fires (proves the analyzer runs here).

//ctguard:secret pin
func DirectBranch(pin string) {
	if pin == "admin" { // want "CT001" "CT002"
		grant()
	}
}
