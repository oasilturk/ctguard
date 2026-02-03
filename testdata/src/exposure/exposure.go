package exposure

import (
	"fmt"
	"log"
	"os"
)

// Test CT004: Secret data exposure through logging/printing

// fmt.Print* functions
//
//ctguard:secret apiKey
func printSecret(apiKey string) {
	fmt.Print(apiKey)             // want "CT004"
	fmt.Printf("key: %s", apiKey) // want "CT004"
	fmt.Println(apiKey)           // want "CT004"
}

// fmt.Sprint* functions
//
//ctguard:secret token
func sprintSecret(token string) string {
	_ = fmt.Sprint(token)               // want "CT004"
	_ = fmt.Sprintf("token: %s", token) // want "CT004"
	return fmt.Sprintln(token)          // want "CT004"
}

// fmt.Fprint* functions
//
//ctguard:secret password
func fprintSecret(password string) {
	fmt.Fprint(os.Stdout, password)            // want "CT004"
	fmt.Fprintf(os.Stdout, "pw: %s", password) // want "CT004"
	fmt.Fprintln(os.Stdout, password)          // want "CT004"
}

// fmt.Errorf - secret in error message
//
//ctguard:secret secret
func errorWithSecret(secret string) error {
	return fmt.Errorf("invalid secret: %s", secret) // want "CT004"
}

// log.Print* functions
//
//ctguard:secret key
func logSecret(key string) {
	log.Print(key)             // want "CT004"
	log.Printf("key: %s", key) // want "CT004"
	log.Println(key)           // want "CT004"
}

// Derived secret - taint propagation
//
//ctguard:secret secret
func derivedSecret(secret string) {
	derived := secret + "-suffix"
	fmt.Println(derived) // want "CT004"
}

// Safe: no secret involved
func safeLogging(message string) {
	fmt.Println(message) // OK - message is not secret
	log.Print(message)   // OK
}

// Safe: secret not passed to output function
//
//ctguard:secret secret
func safeUsage(secret string, public string) {
	_ = len(secret)     // OK - not exposing secret
	fmt.Println(public) // OK - public is not secret
}

// Multiple secrets
//
//ctguard:secret key token
func multipleSecrets(key, token, public string) {
	fmt.Println(key)    // want "CT004"
	fmt.Println(token)  // want "CT004"
	fmt.Println(public) // OK - not marked as secret
}
