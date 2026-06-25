package configsecret

// CheckToken compares token with a non-constant-time ==. token is marked secret
// only via -config (no inline annotation), so CT002 fires only when the config
// reaches the vettool subprocess (Bug B fixture).
func CheckToken(token, expected string) bool {
	return token == expected
}
