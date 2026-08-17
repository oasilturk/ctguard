package taint

// Kind classifies WHAT a tainted value is, which decides which rules may report
// it. KindContent is confidential material (a key, a token, anything annotated);
// KindAuthenticator is an HMAC state and whatever derives from it, which is
// published by design, so only the timing rules apply to it.
//
// The lattice is KindNone < KindAuthenticator < KindContent, joined with max.
// Content dominates so mixing it into an authenticator can never launder it into
// the weaker kind, and the monotone order is what lets the interprocedural fixed
// point converge.
type Kind uint8

const (
	KindNone Kind = iota
	KindAuthenticator
	KindContent
)

// JoinKind returns the least upper bound of two kinds.
func JoinKind(a, b Kind) Kind {
	if a > b {
		return a
	}
	return b
}

func (k Kind) String() string {
	switch k {
	case KindAuthenticator:
		return "authenticator"
	case KindContent:
		return "content"
	default:
		return "none"
	}
}
