package indexing

// Test CT003: Secret-dependent indexing

// Array indexing with secret index - should trigger CT003
//
//ctguard:secret idx
func arrayLookup(idx byte, table [256]byte) byte {
	return table[idx] // want "CT003"
}

// Slice indexing with secret index - should trigger CT003
//
//ctguard:secret key
func sliceLookup(key int, data []byte) byte {
	return data[key] // want "CT003"
}

// Map lookup with secret key - should trigger CT003
//
//ctguard:secret secret
func mapLookup(secret string, m map[string]int) int {
	return m[secret] // want "CT003"
}

// Secret used to compute index - should trigger CT003 (taint propagation)
//
//ctguard:secret key
func derivedIndex(key int, table [16]int) int {
	idx := key & 0xF
	return table[idx] // want "CT003"
}

// Non-secret indexing - should NOT trigger CT003
func safeIndexing(idx int, data []byte) byte {
	return data[idx] // OK - idx is not secret
}

// Secret data being indexed (not secret index) - should NOT trigger CT003
//
//ctguard:secret data
func secretDataAccess(data []byte, idx int) byte {
	return data[idx] // OK - index is not secret, data is
}

// Multiple secret-dependent accesses in same function
//
//ctguard:secret i
func multipleAccesses(i int, arr1, arr2 [10]int) int {
	a := arr1[i] // want "CT003"
	b := arr2[i] // want "CT003"
	return a + b
}

// S-box style lookup (classic crypto pattern)
//
//ctguard:secret input
func sboxTransform(input byte, sbox [256]byte) byte {
	// This is a classic timing side-channel vulnerability
	// An attacker can infer 'input' by measuring cache timing
	return sbox[input] // want "CT003"
}

// Map with ok check - should still trigger
//
//ctguard:secret key
func mapWithOk(key string, m map[string]int) (int, bool) {
	v, ok := m[key] // want "CT003"
	return v, ok
}

// Nested indexing - both should trigger if secret
//
//ctguard:secret i
func nestedIndexing(i int, matrix [4][4]int) int {
	return matrix[i][0] // want "CT003"
}

// Range over slice with secret index used later
//
//ctguard:secret target
func rangeWithSecretIndex(target int, data []int) int {
	for idx, val := range data {
		if idx == target { // CT001 would catch this branch
			return val
		}
	}
	return 0
}

// Slice with secret lower bound - should trigger CT003
//
//ctguard:secret offset
func sliceWithSecretLow(offset int, data []byte) []byte {
	return data[offset:] // want "CT003"
}

// Slice with secret upper bound - should trigger CT003
//
//ctguard:secret length
func sliceWithSecretHigh(length int, data []byte) []byte {
	return data[:length] // want "CT003"
}

// Slice with non-secret bounds - should NOT trigger CT003
func safeSlicing(start, end int, data []byte) []byte {
	return data[start:end] // OK - bounds are not secret
}
