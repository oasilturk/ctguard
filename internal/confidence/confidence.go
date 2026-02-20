package confidence

const ConfidenceTag = "confidence: "

type ConfidenceLevel int

const (
	ConfidenceLow ConfidenceLevel = iota
	ConfidenceHigh
)

func (c ConfidenceLevel) String() string {
	switch c {
	case ConfidenceHigh:
		return "high"
	case ConfidenceLow:
		return "low"
	default:
		return "unknown"
	}
}

func (c ConfidenceLevel) AtLeast(other ConfidenceLevel) bool {
	return c >= other
}

func ParseConfidenceLevel(s string) ConfidenceLevel {
	switch s {
	case "high":
		return ConfidenceHigh
	case "low":
		return ConfidenceLow
	default:
		return ConfidenceLow
	}
}
