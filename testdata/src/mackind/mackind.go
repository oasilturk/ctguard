// Package mackind locks the split between the two kinds of taint. An HMAC is an
// authenticator: it is published by design, so disclosing it (log, print,
// channel, I/O) is not a finding, while the timing rules still apply to it.
// Confidential content reaching those same sinks is still reported, and mixing
// content into an authenticator-tainted value must not launder it.
package mackind

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"os"
)

// --- disclosure of an authenticator is not a finding ---

func publishMAC(key, msg []byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	log.Printf("sig=%x", m.Sum(nil)) // OK
}

func publishEncodedMAC(key, msg []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil)) // OK
}

func macOverChannel(key, msg []byte, ch chan []byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	ch <- m.Sum(nil) // OK
}

//ctguard:isolated
func macToFile(key, msg []byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	_ = os.WriteFile("/tmp/sig", m.Sum(nil), 0o600) // OK
}

// The kind crosses the call boundary: this helper only ever receives a MAC.
func macIntoHelper(key, msg []byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	emitMAC(m.Sum(nil))
}

func emitMAC(sig []byte) {
	log.Printf("%x", sig) // OK
}

// The kind also survives two levels of return, whatever order the fixed point
// visits the functions in.
func innerTag(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func outerTag(key, msg []byte) []byte {
	return innerTag(key, msg)
}

func publishChainedMAC(key, msg []byte) {
	log.Printf("%x", outerTag(key, msg)) // OK
}

// A confidential value handed to a MAC method comes back out as content, since
// hash.Sum appends the digest to the slice it is given.
//
//ctguard:secret key
func publishSumOntoKey(key, msg []byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	log.Printf("%x", m.Sum(key)) // want "CT004"
}

// --- the timing rules still apply to an authenticator ---

func compareMAC(key, msg, sig []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return bytes.Equal(m.Sum(nil), sig) // want "CT002.*confidence: high"
}

// The kind survives an encoder, so the encoded compare is still reported.
func compareEncodedMAC(key, msg []byte, sig string) bool {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil)) == sig // want "CT002.*confidence: low"
}

func computeTag(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// The MAC is produced in another function, and the authenticator kind crosses
// the return with it.
func compareCrossFunction(key, msg, sig []byte) bool {
	return bytes.Equal(computeTag(key, msg), sig) // want "CT002.*confidence: low"
}

// --- confidential content is still reported at the disclosure sinks ---

//ctguard:secret key
func publishKey(key []byte) {
	log.Printf("key=%x", key) // want "CT004"
}

//ctguard:secret key
func keyOverChannel(key []byte, ch chan []byte) {
	ch <- key // want "CT006"
}

//ctguard:isolated
//ctguard:secret key
func keyToFile(key []byte) {
	_ = os.WriteFile("/tmp/key", key, 0o600) // want "CT007"
}

//ctguard:secret key
func keyIntoHelper(key []byte) {
	emitKey(key)
}

func emitKey(v []byte) {
	log.Printf("%x", v) // want "CT004"
}

// --- content must not be laundered into the authenticator kind ---

// Both a MAC and a key reach the sink: the kinds join to content, so it reports.
//
//ctguard:secret key
func publishBoth(key, msg []byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	log.Printf("%x %x", m.Sum(nil), key) // want "CT004"
}

// Same, but the key is mixed in through a call the analyzer cannot inspect.
//
//ctguard:secret key
func publishMixed(key, msg []byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	mixed := append(m.Sum(nil), key...)
	log.Printf("%x", mixed) // want "CT004"
}

// --- content must survive every path the kind travels on ---

// Append* returns its destination grown in place, so the destination is a
// source of the result exactly as the encoded input is.
//
//ctguard:secret key
func appendOntoKey(key, msg []byte) {
	log.Printf("%x", hex.AppendEncode(key, msg)) // want "CT004"
}

//ctguard:secret key
func appendOntoKeyBase64(key, msg []byte) {
	log.Printf("%x", base64.StdEncoding.AppendEncode(key, msg)) // want "CT004"
}

//ctguard:secret key
func compareAppendedKey(key, msg, other []byte) bool {
	return bytes.Equal(hex.AppendEncode(key, msg), other) // want "CT002"
}

// A bound method value drops the receiver from the argument list, so the
// encoder must not depend on a fixed argument position.
//
//ctguard:secret key
func boundEncoder(key []byte) {
	enc := base64.StdEncoding.EncodeToString
	log.Print(enc(key)) // want "CT004"
}

// A whole-object store must not mask a field written afterwards.
//
//ctguard:secret key
func wholeObjectThenKey(key, msg []byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	tmp := box{sig: m.Sum(nil)}
	b := tmp
	b.key = key
	log.Printf("%x", b.key) // want "CT004"
}

// Element writes are element-blind, so one MAC byte landing in a confidential
// buffer must not reclassify the buffer.
//
//ctguard:secret buf
func macByteIntoSecretBuffer(buf, key, msg []byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	buf[0] = m.Sum(nil)[0]
	log.Printf("%x", buf[1]) // want "CT004"
}

// What a callee returns on its own outranks the kind of the arguments handed
// to it: this one returns an annotated secret while taking a MAC.
//
//ctguard:secret master
func passthrough(master, tag []byte) []byte {
	return master
}

func callPassthroughWithMAC(key, msg []byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	log.Printf("%x", passthrough(key, m.Sum(nil))) // want "CT004"
}

// --- known blind spot: an HMAC whose output is itself a secret ---

// A hand-rolled KDF is the same expression as a MAC tag, so its result is
// classified as an authenticator and disclosing it is not reported. Annotating
// the consumer restores content taint, which is the documented workaround.
func deriveSubkey(ikm, salt []byte) []byte {
	m := hmac.New(sha256.New, ikm)
	m.Write(salt)
	return m.Sum(nil)
}

func publishSubkey(ikm, salt []byte) {
	log.Printf("%x", deriveSubkey(ikm, salt)) // OK (blind spot)
}

//ctguard:secret subkey
func publishAnnotatedSubkey(subkey []byte) {
	log.Printf("%x", subkey) // want "CT004"
}

func useAnnotatedSubkey(ikm, salt []byte) {
	publishAnnotatedSubkey(deriveSubkey(ikm, salt))
}

// The same shape, and the wider half of the blind spot: here the tag IS the
// capability, so logging it hands out a working reset link. What the code does
// with a MAC is invisible, so this reads exactly like publishEncodedMAC above.
func resetToken(secret []byte, userID string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(userID))
	return hex.EncodeToString(m.Sum(nil))
}

func mailResetLink(secret []byte, userID string) {
	log.Printf("reset link: /reset?t=%s", resetToken(secret, userID)) // OK (blind spot)
}

// Annotating the consumer is the workaround, and the annotation wins: the
// argument arrives as an authenticator but the param is declared content, and
// the join keeps it content rather than laundering it away.
//
//ctguard:secret token
func logResetToken(token string) {
	log.Printf("token=%s", token) // want "CT004"
}

func useResetToken(secret []byte, userID string) {
	logResetToken(resetToken(secret, userID))
}

// A struct holding both: the MAC field discloses nothing, the key field does.
type box struct {
	sig []byte
	key []byte
}

//ctguard:secret key
func publishBoxKey(key, msg []byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	b := box{sig: m.Sum(nil), key: key}
	log.Printf("%x", b.key) // want "CT004"
}

func publishBoxSig(key, msg []byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	b := box{sig: m.Sum(nil)}
	log.Printf("%x", b.sig) // OK
}
