// Package isr implements the Deep Blue Project ISR analytics data model:
// mandatory classification labelling on every sensor event, clearance-based
// read enforcement and multi-modal ingestion discipline. All handling is
// fail-closed: a missing or unknown classification label is rejected, never
// defaulted.
package isr

import (
	"errors"
	"fmt"
	"strings"
)

// Classification is the national-security classification label carried by
// every ISR event, track, anomaly and outcome record. The rank orders the
// labels so clearance checks are a single comparison.
type Classification string

const (
	ClassificationUnclassified Classification = "UNCLASSIFIED"
	ClassificationRestricted   Classification = "RESTRICTED"
	ClassificationConfidential Classification = "CONFIDENTIAL"
	ClassificationSecret       Classification = "SECRET"
)

// ErrInvalidClassification is returned when a label is absent or unknown.
var ErrInvalidClassification = errors.New("classification must be one of UNCLASSIFIED, RESTRICTED, CONFIDENTIAL, SECRET")

// ParseClassification validates a raw label fail-closed. Blank, mixed-case
// and unknown values are rejected.
func ParseClassification(raw string) (Classification, error) {
	switch Classification(raw) {
	case ClassificationUnclassified, ClassificationRestricted, ClassificationConfidential, ClassificationSecret:
		return Classification(raw), nil
	default:
		return "", ErrInvalidClassification
	}
}

// MustClassification validates an internal label; it panics only on a
// programming error (a constant outside the approved set).
func MustClassification(value Classification) Classification {
	if _, err := ParseClassification(string(value)); err != nil {
		panic(fmt.Sprintf("isr: invalid classification constant %q", value))
	}
	return value
}

// Rank returns the ordinal sensitivity of the label (higher is more
// sensitive). Unknown labels rank as Secret so comparisons fail closed.
func (label Classification) Rank() int {
	switch label {
	case ClassificationUnclassified:
		return 0
	case ClassificationRestricted:
		return 1
	case ClassificationConfidential:
		return 2
	default:
		return 3
	}
}

// Covers reports whether a principal holding this label as clearance may read
// material labelled `event`. Fail-closed: an invalid clearance covers nothing.
func (label Classification) Covers(event Classification) bool {
	if _, err := ParseClassification(string(label)); err != nil {
		return false
	}
	if _, err := ParseClassification(string(event)); err != nil {
		return false
	}
	return label.Rank() >= event.Rank()
}

// MaxClassification returns the more sensitive of two valid labels. Track
// classification is the maximum over its associated detections.
func MaxClassification(a, b Classification) Classification {
	if a.Rank() >= b.Rank() {
		return a
	}
	return b
}

// canonicalClassificationList is used by CHECK-constraint generation and
// documentation so the approved label set has exactly one source of truth.
func CanonicalClassificationList() string {
	labels := []string{
		string(ClassificationUnclassified), string(ClassificationRestricted),
		string(ClassificationConfidential), string(ClassificationSecret),
	}
	return strings.Join(labels, ", ")
}
