package taint

import (
	"testing"

	"golang.org/x/tools/go/analysis/passes/buildssa"

	"github.com/oasilturk/ctguard/internal/annotations"
)

func TestJoinKindIsMonotoneAndContentDominates(t *testing.T) {
	cases := []struct {
		a, b, want Kind
	}{
		{KindNone, KindNone, KindNone},
		{KindNone, KindAuthenticator, KindAuthenticator},
		{KindNone, KindContent, KindContent},
		{KindAuthenticator, KindAuthenticator, KindAuthenticator},
		{KindAuthenticator, KindContent, KindContent},
		{KindContent, KindAuthenticator, KindContent},
		{KindContent, KindContent, KindContent},
	}
	for _, c := range cases {
		if got := JoinKind(c.a, c.b); got != c.want {
			t.Errorf("JoinKind(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
		if got := JoinKind(c.b, c.a); got != c.want {
			t.Errorf("JoinKind is not commutative for (%v, %v)", c.a, c.b)
		}
		// A join never moves a kind down, which is what keeps the fixed point
		// converging.
		if JoinKind(c.a, c.b) < c.a || JoinKind(c.a, c.b) < c.b {
			t.Errorf("JoinKind(%v, %v) moved down to %v", c.a, c.b, JoinKind(c.a, c.b))
		}
	}
}

// An annotated param is confidential material, and a MAC built in the body is
// an authenticator: the two kinds must not be confused across the return.
func TestReturnKindClassifiesMACAndAnnotation(t *testing.T) {
	src := `
package test

import (
	"crypto/hmac"
	"crypto/sha256"
)

func CtguardTagProbe(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func CtguardCopyProbe(key []byte) []byte {
	out := make([]byte, 0, len(key))
	return append(out, key...)
}
`

	ssaRes, err := buildTestSSA(src)
	if err != nil {
		t.Fatalf("Failed to build SSA: %v", err)
	}

	secrets := annotations.Secrets{
		FuncSecretParams: map[string]map[string]bool{
			"test.CtguardCopyProbe": {"key": true},
		},
	}

	ia := NewInterproceduralAnalyzer(ssaRes, secrets)
	ia.Analyze()

	tag := findFunction(ssaRes, "CtguardTagProbe")
	if tag == nil {
		t.Fatal("Could not find Tag function")
	}
	if !ia.IntrinsicReturn(tag) {
		t.Fatal("Tag should intrinsically return taint (the MAC)")
	}
	if got := ia.IntrinsicReturnKind(tag); got != KindAuthenticator {
		t.Errorf("Tag return kind = %v, want authenticator", got)
	}

	cp := findFunction(ssaRes, "CtguardCopyProbe")
	if cp == nil {
		t.Fatal("Could not find Copy function")
	}
	if got := ia.IntrinsicReturnKind(cp); got != KindContent {
		t.Errorf("Copy return kind = %v, want content", got)
	}
}

// An unanalyzed function must never be reported as an authenticator: the weaker
// kind has to be earned, so the fallback is content.
func TestUnknownFunctionDefaultsToContent(t *testing.T) {
	ia := NewInterproceduralAnalyzer(&buildssa.SSA{}, annotations.Secrets{})

	if got := ia.IntrinsicReturnKind(nil); got != KindContent {
		t.Errorf("unknown func intrinsic return kind = %v, want content", got)
	}
	if got := ia.ReturnKind(nil); got != KindContent {
		t.Errorf("unknown func return kind = %v, want content", got)
	}

	d := NewDepender(nil, map[string]bool{"key": true}, nil)
	if got := d.paramKind("key"); got != KindContent {
		t.Errorf("param with no recorded kind = %v, want content", got)
	}
}
