package branches

// CT001: Secret-dependent branch tests

//ctguard:secret secret
func secretBranch(secret int, public int) int {
	if secret == 0 { // want "CT001"
		return 1
	}
	if public == 0 {
		return 2
	}
	derived := secret + 1
	if derived > 0 { // want "CT001"
		return 3
	}
	return 4
}
