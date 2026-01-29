package a

//ctguard:secret k
func f(k int, x int) int {
	if k == 0 { // want "CT001"
		return 1
	}
	if x == 0 {
		return 2
	}
	y := k + 1
	if y > 0 { // want "CT001"
		return 3
	}
	return 4
}
