package poolmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"sync"
)

// A sync.Pool whose New returns an HMAC yields MAC state on Get(); a pooled
// mac.Sum() compared in non-constant time must be flagged with no annotation.
// Mirrors the MartialBE/one-hub token validator.

var macKey = []byte("server-secret")

var hmacPool = sync.Pool{New: func() any { return hmac.New(sha256.New, macKey) }}

func ValidateToken(payload, receivedSig []byte) bool {
	h := hmacPool.Get().(hash.Hash)
	defer func() {
		h.Reset()
		hmacPool.Put(h)
	}()
	h.Write(payload)
	expected := h.Sum(nil)
	return bytes.Equal(receivedSig, expected) // want "CT002"
}

// A pool whose New does NOT return a MAC must not taint its Get() result.
var bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func compareBuffered(x, y []byte) bool {
	b := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(b)
	b.Write(x)
	return bytes.Equal(b.Bytes(), y) // OK: not a MAC pool
}
