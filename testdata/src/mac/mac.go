package mac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// CT002: HMAC output compared in non-constant time. These need no
// //ctguard:secret annotation: an HMAC result is secret-equivalent by
// construction, so the compare is flagged on its own. Mirrors the real
// acquia/http-hmac-go and altcha-org/altcha-lib-go bugs.

func verifyInlineEqual(key, msg, sig []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return bytes.Equal(mac.Sum(nil), sig) // want "CT002"
}

func verifyInlineOperator(key, msg []byte, sig string) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil)) == sig // want "CT002"
}

func computeMAC(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// Return-boundary: the MAC is produced in computeMAC and compared here.
func verifyCrossFunction(key, msg, sig []byte) bool {
	return bytes.Equal(computeMAC(key, msg), sig) // want "CT002"
}

//ctguard:secret key
func verifyAnnotated(key, msg, sig []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return bytes.Equal(mac.Sum(nil), sig) // want "CT002"
}

// hmac.Equal is constant-time and must NOT be flagged.
func verifySafe(key, msg, sig []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return hmac.Equal(mac.Sum(nil), sig) // OK
}
