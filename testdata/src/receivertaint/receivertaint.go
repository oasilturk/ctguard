package receivertaint

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// Context-sensitive return taint: a passthrough constructor (newParser) whose
// result field is tainted only because SOME caller passed a secret must not taint
// an unrelated call site whose argument is public. Mirrors the mjl-/mox SCRAM
// cascade, where this leak tainted a stateful receiver's public fields.

type parser struct {
	s     string
	lower string
}

func newParser(buf string) *parser {
	return &parser{s: buf, lower: buf}
}

// deriveAndParse feeds a SECRET (an HMAC) into newParser. This makes newParser's
// return-field taint param-derived; that fact must stay local to this call site.
func deriveAndParse(key, msg []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	p := newParser(string(mac.Sum(nil)))
	return p.lower
}

// classify calls newParser with PUBLIC input. The result fields must be clean, so
// this comparison must NOT flag. Before the intrinsic/param-derived split, the
// param-derived ReturnFields of newParser leaked here and this was falsely flagged.
func classify(publicInput, other string) bool {
	p := newParser(publicInput)
	return p.lower == other // OK: newParser wrapped public data here
}

type Server struct {
	h     func() hash.Hash
	nonce string // public protocol value
}

func hmac0(h func() hash.Hash, key, msg []byte) []byte {
	m := hmac.New(h, key)
	m.Write(msg)
	return m.Sum(nil)
}

// Finish reads a public receiver field (nonce) and separately verifies a MAC. Only
// the MAC comparison is a finding; the public nonce compare must stay clean.
func (s *Server) Finish(clientFinal string, saltedPassword, proof []byte) bool {
	if clientFinal != s.nonce { // OK: public protocol values
		return false
	}
	clientSig := hmac0(s.h, saltedPassword, []byte("Client Key"))
	return bytes.Equal(clientSig, proof) // want "CT002"
}

// FN guard: a constructor that takes a MAC as a parameter and stores it in a
// field must STILL be flagged when the argument is an intrinsic MAC. The fix seeds
// param-derived return-field taint whenever a tainted argument flows into the call,
// so this must not become a false negative.
type response struct{ MAC []byte }

func newResponse(mac []byte) *response { return &response{MAC: mac} }

func verifyViaCtor(key, msg, provided []byte) bool {
	r := newResponse(hmac0(sha256.New, key, msg))
	return bytes.Equal(r.MAC, provided) // want "CT002"
}

func run(h func() hash.Hash, cf, cfin string, sp, proof []byte) bool {
	_ = deriveAndParse(sp, []byte(cf))
	_ = classify(cf, cfin)
	srv := &Server{h: h, nonce: cf}
	return srv.Finish(cfin, sp, proof)
}
