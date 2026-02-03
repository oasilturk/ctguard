package ignores

import (
	"bytes"
	"fmt"
)

// Test ignore functionality

// Function-level ignore - all CT002 in this function should be ignored
//
//ctguard:ignore CT002 -- this function uses constant-time comparison internally
//ctguard:secret key
func functionLevelIgnore(key []byte, expected []byte) bool {
	return bytes.Equal(key, expected) // Should be ignored (function-level)
}

// Line-level ignore with comment at end of line
//
//ctguard:secret key
func lineLevelIgnoreInline(key []byte, expected []byte) bool {
	return bytes.Equal(key, expected) //ctguard:ignore CT002 -- safe here
}

// Line-level ignore with comment on previous line
//
//ctguard:secret key
func lineLevelIgnoreAbove(key []byte, expected []byte) bool {
	//ctguard:ignore CT002
	return bytes.Equal(key, expected)
}

// Partial ignore - only specific rule ignored
//
//ctguard:ignore CT002
//ctguard:secret key
func partialIgnore(key []byte, expected []byte) bool {
	if len(key) > 0 { // CT001 should still trigger (not ignored)
		return bytes.Equal(key, expected) // CT002 ignored
	}
	return false
}

// No ignore - should report all findings
//
//ctguard:secret key
func noIgnore(key []byte, expected []byte) bool {
	return bytes.Equal(key, expected) // Should report CT002
}

// Ignore all rules
//
//ctguard:ignore
//ctguard:secret key
func ignoreAll(key []byte, data []byte) {
	if len(key) > 0 { // CT001 ignored
		fmt.Println(key) // CT004 ignored
	}
}

// Multiple rules ignored
//
//ctguard:ignore CT001 CT004
//ctguard:secret key
func ignoreMultiple(key []byte, data []byte) {
	if len(key) > 0 { // CT001 ignored
		fmt.Println(key) // CT004 ignored
	}
	_ = bytes.Equal(key, data) // CT002 NOT ignored - should report
}

// Mixed: function-level and line-level
//
//ctguard:ignore CT001
//ctguard:secret key
func mixedIgnore(key []byte, expected []byte) bool {
	if len(key) > 0 { // CT001 ignored (function-level)
		return bytes.Equal(key, expected) //ctguard:ignore CT002
	}
	return bytes.Equal(key, expected) // CT002 NOT ignored - should report
}
