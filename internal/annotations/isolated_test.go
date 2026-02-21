package annotations

import (
	"testing"
)

func TestParseIsolatedDirective(t *testing.T) {
	tests := []struct {
		name string
		text string
		want isolatedKind
	}{
		// Function-level
		{
			name: "plain isolated",
			text: "//ctguard:isolated",
			want: isolatedKindFunc,
		},
		{
			name: "isolated with leading space",
			text: "// ctguard:isolated",
			want: isolatedKindFunc,
		},
		{
			name: "isolated with trailing space",
			text: "//ctguard:isolated   ",
			want: isolatedKindFunc,
		},
		{
			name: "isolated with reason",
			text: "//ctguard:isolated -- this function handles crypto",
			want: isolatedKindFunc,
		},

		// Begin
		{
			name: "isolated begin",
			text: "//ctguard:isolated begin",
			want: isolatedKindBegin,
		},
		{
			name: "isolated begin with spaces",
			text: "// ctguard:isolated begin",
			want: isolatedKindBegin,
		},
		{
			name: "isolated begin with reason",
			text: "//ctguard:isolated begin -- start of critical section",
			want: isolatedKindBegin,
		},

		// End
		{
			name: "isolated end",
			text: "//ctguard:isolated end",
			want: isolatedKindEnd,
		},
		{
			name: "isolated end with spaces",
			text: "// ctguard:isolated end",
			want: isolatedKindEnd,
		},
		{
			name: "isolated end with reason",
			text: "//ctguard:isolated end -- end of critical section",
			want: isolatedKindEnd,
		},

		// Not an isolated directive
		{
			name: "not isolated - secret",
			text: "//ctguard:secret key",
			want: isolatedKindNone,
		},
		{
			name: "not isolated - ignore",
			text: "//ctguard:ignore CT001",
			want: isolatedKindNone,
		},
		{
			name: "not isolated - empty",
			text: "",
			want: isolatedKindNone,
		},
		{
			name: "not isolated - regular comment",
			text: "// This is a regular comment",
			want: isolatedKindNone,
		},
		{
			name: "not isolated - unknown suffix",
			text: "//ctguard:isolated unknown",
			want: isolatedKindNone,
		},
		{
			name: "not isolated - block comment",
			text: "/* ctguard:isolated */",
			want: isolatedKindNone,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseIsolatedDirective(tc.text)
			if got != tc.want {
				t.Errorf("parseIsolatedDirective(%q) = %v, want %v", tc.text, got, tc.want)
			}
		})
	}
}

func TestIsolatedRegions_IsIsolated(t *testing.T) {
	t.Run("nil regions", func(t *testing.T) {
		var ir *IsolatedRegions
		if ir.IsIsolated(nil, 0, "foo") {
			t.Error("nil IsolatedRegions.IsIsolated should return false")
		}
	})

	t.Run("empty regions", func(t *testing.T) {
		ir := &IsolatedRegions{
			FuncIsolated: make(map[string]bool),
			BlockRegions: make(map[string][]LineRange),
		}
		if ir.IsIsolated(nil, 0, "foo") {
			t.Error("empty IsolatedRegions.IsIsolated should return false for unknown func")
		}
	})

	t.Run("function isolated by name", func(t *testing.T) {
		ir := &IsolatedRegions{
			FuncIsolated: map[string]bool{
				"MyFunc": true,
			},
			BlockRegions: make(map[string][]LineRange),
		}
		if !ir.IsIsolated(nil, 0, "MyFunc") {
			t.Error("MyFunc should be isolated")
		}
		if ir.IsIsolated(nil, 0, "OtherFunc") {
			t.Error("OtherFunc should not be isolated")
		}
	})
}

func TestLineRange(t *testing.T) {
	lr := LineRange{Start: 10, End: 20}
	if lr.Start != 10 || lr.End != 20 {
		t.Errorf("LineRange fields incorrect: got Start=%d End=%d", lr.Start, lr.End)
	}
}
