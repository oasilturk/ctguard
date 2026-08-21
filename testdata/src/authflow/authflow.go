// Package authflow models the credential check of an HTTP API gateway: a bearer
// token arrives in a request header, the gateway rebuilds the header value it
// expects from the tenant's API key, and compares the two. The key is never used
// at the comparison itself. It reaches it through helpers, which exercises
// interprocedural propagation in both directions: out of a helper's return value
// and into a helper's parameter.
package authflow

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"strings"
)

const (
	bearerScheme = "Bearer "
	legacyPlan   = "legacy"
)

// Tenant is the server-side record of an API client. Every field is public
// routing data; owning a key must not make them secret.
type Tenant struct {
	ID    string
	Plan  string
	Debug bool
}

// bearerHeader renders the Authorization header value for an API key. Its result
// is exactly as secret as its argument, which is the caller's business.
func bearerHeader(key string) string {
	return bearerScheme + key
}

// expectedCredential is the second hop: legacy tenants still send the raw key,
// everyone else sends the bearer form.
func expectedCredential(t Tenant, apiKey string) string {
	if t.Plan == legacyPlan { // OK: the plan is public routing data
		return apiKey
	}
	return bearerHeader(apiKey)
}

// credentialMatches uses a regular string comparison on a secret-derived
// value, which CTGuard treats as a non-constant-time comparison pattern.
func credentialMatches(presented, expected string) bool {
	return presented == expected // want "CT002"
}

// auditRejected records a rejected request. The tenant ID is fine to log; the
// expected header value is the credential itself.
func auditRejected(tenantID, expected string) {
	log.Printf("authflow: tenant %s presented an invalid token, expected %q", tenantID, expected) // want "CT004"
}

// Authorize is the middleware entry point.
//
//ctguard:secret apiKey
func Authorize(r *http.Request, t Tenant, apiKey string) (bool, error) {
	presented := r.Header.Get("Authorization")

	// Public protocol check on a public value: not a finding.
	if !strings.HasPrefix(presented, bearerScheme) { // OK
		return false, fmt.Errorf("authflow: tenant %s must use the %s scheme", t.ID, bearerScheme) // OK
	}

	expected := expectedCredential(t, apiKey)
	if t.Debug { // OK: public flag
		auditRejected(t.ID, expected)
	}
	return credentialMatches(presented, expected), nil
}

// AuthorizeConstantTime is the remediation. The same value reaches the same
// comparison point through the same helpers, but in constant time, so it is not
// reported: what silences the rule is the sanitizer, not a lost taint.
//
//ctguard:secret apiKey
func AuthorizeConstantTime(r *http.Request, t Tenant, apiKey string) bool {
	presented := r.Header.Get("Authorization")
	expected := expectedCredential(t, apiKey)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1 // OK
}
