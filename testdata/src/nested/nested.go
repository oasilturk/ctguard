package nested

// Test nested branches with secret data

//ctguard:secret key
func nestedBranches(key int, x int) int {
	// Outer branch on secret
	if key > 0 { // want "CT001"
		// Nested branch on secret-derived value
		y := key * 2
		if y > 10 { // want "CT001"
			return 1
		}
		// Nested branch on non-secret - should be OK
		if x > 5 {
			return 2
		}
	}
	return 0
}

//ctguard:secret token
func deepNesting(token string, a, b, c int) int {
	if a > 0 {
		if b > 0 {
			if len(token) > 0 { // want "CT001"
				if c > 0 {
					return 1
				}
			}
		}
	}
	return 0
}
