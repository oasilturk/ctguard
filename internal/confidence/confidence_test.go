package confidence

import "testing"

func TestConfidenceLevel_String(t *testing.T) {
	tests := []struct {
		name     string
		c        ConfidenceLevel
		expected string
	}{
		{"low", ConfidenceLow, "low"},
		{"high", ConfidenceHigh, "high"},
		{"unknown value", ConfidenceLevel(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.String(); got != tt.expected {
				t.Errorf("String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfidenceLevel_AtLeast(t *testing.T) {
	tests := []struct {
		name     string
		c        ConfidenceLevel
		other    ConfidenceLevel
		expected bool
	}{
		{"high >= low", ConfidenceHigh, ConfidenceLow, true},
		{"high >= high", ConfidenceHigh, ConfidenceHigh, true},
		{"low >= low", ConfidenceLow, ConfidenceLow, true},
		{"low >= high", ConfidenceLow, ConfidenceHigh, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.AtLeast(tt.other); got != tt.expected {
				t.Errorf("AtLeast() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseConfidenceLevel(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		expected ConfidenceLevel
	}{
		{"low", "low", ConfidenceLow},
		{"high", "high", ConfidenceHigh},
		{"uppercase", "HIGH", ConfidenceLow},
		{"empty", "", ConfidenceLow},
		{"invalid", "medium", ConfidenceLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseConfidenceLevel(tt.s); got != tt.expected {
				t.Errorf("ParseConfidenceLevel(%q) = %v, want %v", tt.s, got, tt.expected)
			}
		})
	}
}
