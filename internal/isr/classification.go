package isr

import (
	"errors"
	"strings"
)

// Classification is the mandatory national-security label carried by every
// ISR event, track, anomaly and outcome record. The label set is closed and
// ordered; comparisons are used for clearance enforcement.
type Classification string

const (
	ClassificationUnclassified Classification = "UNCLASSIFIED"
	ClassificationRestricted   Classification = "RESTRICTED"
	ClassificationConfidential Classification = "CONFIDENTIAL"
	ClassificationSecret       Classification = "SECRET"
)

// ErrInvalidClassification rejects a missing or unrecognized label. All
// parsing is fail-closed: any value outside the approved set is an error.
var ErrInvalidClassification = errors.New("classification label must be one of UNCLASSIFIED, RESTRICTED, CONFIDENTIAL, SECRET")

// ParseClassification validates a label fail-closed (case-insensitive input
// is normalised to the canonical uppercase form).
func ParseClassification(raw string) (Classification, error) {
	switch Classification(strings.ToUpper(strings.TrimSpace(raw))) {
	case ClassificationUnclassified:
		return ClassificationUnclassified, nil
	case ClassificationRestricted:
		return ClassificationRestricted, nil
	case ClassificationConfidential:
		return ClassificationConfidential, nil
	case ClassificationSecret:
		return ClassificationSecret, nil
	default:
		return "", ErrInvalidClassification
	}
}

// Rank orders labels for clearance comparison (higher is more sensitive).
func (label Classification) Rank() int {
	switch label {
	case ClassificationSecret:
		return 3
	case ClassificationConfidential:
		return 2
	case ClassificationRestricted:
		return 1
	default:
		return 0
	}
}

// Covers reports whether a principal cleared at this level may read a record
// carrying the other label.
func (label Classification) Covers(other Classification) bool {
	return label.Rank() >= other.Rank()
}

// Max returns the more sensitive of two labels, used when fused records
// inherit the highest classification of their inputs.
func Max(a, b Classification) Classification {
	if a.Rank() >= b.Rank() {
		return a
	}
	return b
}
