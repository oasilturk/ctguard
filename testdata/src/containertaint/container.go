package containertaint

// Container-root taint: a secret written into a struct/slice field taints the
// containing value, so return-value and receiver propagation carry it across
// calls. Minimized from Vault's Shamir mult(); without it the chain breaks at
// the ctor return and the table lookups are never reported.

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
