package fieldtaint

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
)

// Field-sensitive taint: a struct carrying a MAC in one field must not taint its
// sibling public fields across call and return boundaries, while the MAC field
// itself stays tainted. Mirrors the acquia/altcha response-struct pattern.

type resp struct {
	Algorithm string // public selector, not secret
	MAC       []byte // HMAC, secret-equivalent
}

func mkMAC(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// A: composite passed by value; reading the PUBLIC field must not flag.
func dispatchA(r resp) string {
	switch r.Algorithm { // OK
	case "SHA-256":
		return "a1"
	}
	return "a0"
}

// B: by-value param; comparing the SECRET field must still flag.
func verifyB(r resp, provided []byte) bool {
	return bytes.Equal(r.MAC, provided) // want "CT002"
}

// C: struct returned from a function; public field clean, secret field flagged.
func buildC(key, msg []byte) resp {
	return resp{Algorithm: "SHA-256", MAC: mkMAC(key, msg)}
}

func useCpublic(key, msg []byte) string {
	r := buildC(key, msg)
	switch r.Algorithm { // OK
	case "SHA-256":
		return "c1"
	}
	return "c0"
}

func useCsecret(key, msg, provided []byte) bool {
	r := buildC(key, msg)
	return bytes.Equal(r.MAC, provided) // want "CT002"
}

func runA(key, msg []byte) string {
	r := resp{Algorithm: "SHA-256", MAC: mkMAC(key, msg)}
	return dispatchA(r)
}

func runB(key, msg, provided []byte) bool {
	r := resp{Algorithm: "SHA-256", MAC: mkMAC(key, msg)}
	return verifyB(r, provided)
}

// ANNO: an annotated whole-struct secret still taints every field.
//
//ctguard:secret whole
func annotatedWhole(whole resp, provided []byte) bool {
	return bytes.Equal(whole.MAC, provided) // want "CT002"
}
