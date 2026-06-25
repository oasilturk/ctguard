package containertaint

// Container-root taint: a secret written into a struct/slice field taints the
// containing value, so return-value and receiver propagation carry it across
// calls. Minimized from Vault's Shamir mult(); without it the chain breaks at
// the ctor return and the table lookups are never reported.

import "fmt"

var logTable = [256]byte{}
var expTable = [256]byte{}

type polynomial struct {
	coefficients []uint8
}

func makePolynomial(intercept uint8, degree uint8) polynomial {
	p := polynomial{coefficients: make([]uint8, degree+1)}
	p.coefficients[0] = intercept
	return p
}

func (p *polynomial) leaf() uint8 {
	coeff := p.coefficients[0]
	return mult(coeff, 3)
}

func mult(a, b uint8) uint8 {
	log_a := logTable[a] // want "CT003"
	log_b := logTable[b]
	sum := (int(log_a) + int(log_b)) % 255 // want "CT005"
	return expTable[sum]                   // want "CT003"
}

//ctguard:secret seed
func driver(seed uint8) uint8 {
	p := makePolynomial(seed, 3)
	return p.leaf()
}

// Field-qualified taint: a secret in one field must not taint sibling fields.

type record struct {
	data   []byte
	offset int
}

//ctguard:secret key
func siblingClean(key []byte) {
	r := &record{}
	r.data = key
	fmt.Println(r.offset) // sibling field, no finding
}

//ctguard:secret key
func sameFieldFlagged(key []byte) {
	r := &record{}
	r.data = key
	fmt.Println(r.data) // want "CT004"
}

type outer struct {
	inner record
	tag   int
}

//ctguard:secret key
func nestedSiblingClean(key []byte) {
	o := &outer{}
	o.inner.data = key
	fmt.Println(o.tag)          // nested sibling, no finding
	fmt.Println(o.inner.offset) // nested sibling, no finding
}

// Constructor idiom: the field root is an (unstable) call result, not an Alloc.
// Field taint must still key on it, same-field flagged and sibling clean.

func newRecord() *record { return &record{} }

//ctguard:secret key
func callRootSameField(key []byte) {
	r := newRecord()
	r.data = key
	fmt.Println(r.data) // want "CT004"
}

//ctguard:secret key
func callRootSibling(key []byte) {
	r := newRecord()
	r.data = key
	fmt.Println(r.offset) // sibling, no finding
}

// Whole-struct read of a pointer renders the secret field, so it must flag.
//
//ctguard:secret key
func wholeStructRead(key []byte, r *record) {
	r.data = key
	fmt.Println(*r) // want "CT004"
}
