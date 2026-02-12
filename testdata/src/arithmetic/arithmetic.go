package arithmetic

import (
	"math"
	"math/bits"
)

// Test CT005: Variable-time arithmetic operations on secrets

//ctguard:secret key
func divideBySecret(key int, value int) int {
	return value / key // want "CT005"
}

//ctguard:secret divisor
func divideSecret(divisor int, value int) int {
	return value / divisor // want "CT005"
}

//ctguard:secret key
func moduloBySecret(key int, value int) int {
	return value % key // want "CT005"
}

//ctguard:secret data
func moduloSecret(data int, modulus int) int {
	return data % modulus // want "CT005"
}

//ctguard:secret shift
func leftShiftBySecret(shift uint, value byte) byte {
	return value << shift // want "CT005"
}

//ctguard:secret shift
func rightShiftBySecret(shift uint, value byte) byte {
	return value >> shift // want "CT005"
}

//ctguard:secret data
func shiftSecret(data uint, amount uint) uint {
	return data << amount // want "CT005"
}

//ctguard:secret key
func addSecret(key int, value int) int {
	return key + value // OK
}

//ctguard:secret key
func subtractSecret(key int, value int) int {
	return key - value // OK
}

//ctguard:secret key
func multiplySecret(key int, value int) int {
	return key * value // OK
}

//ctguard:secret key
func xorSecret(key byte, value byte) byte {
	return key ^ value // OK
}

//ctguard:secret key
func andSecret(key byte, value byte) byte {
	return key & value // OK
}

//ctguard:secret key
func orSecret(key byte, value byte) byte {
	return key | value // OK
}

//ctguard:secret secret
func divideSecretByConstant(secret int) int {
	return secret / 10 // want "CT005"
}

//ctguard:secret divisor
func divideConstantBySecret(divisor int) int {
	return 1000 / divisor // want "CT005"
}

//ctguard:secret key
func derivedArithmetic(key int) int {
	derived := key * 2
	return derived / 3 // want "CT005"
}

func safeArithmetic(a, b int) int {
	return a / b // OK
}

//ctguard:secret x
func mathMod(x, y float64) float64 {
	return math.Mod(x, y) // want "CT005"
}

//ctguard:secret x
func mathRemainder(x, y float64) float64 {
	return math.Remainder(x, y) // want "CT005"
}

//ctguard:secret n
func rotateLeftSecret(n int) uint {
	return bits.RotateLeft(uint(n), 3) // want "CT005"
}

//ctguard:secret data
func rotateLeft8Secret(data uint8) uint8 {
	return bits.RotateLeft8(data, 2) // want "CT005"
}
