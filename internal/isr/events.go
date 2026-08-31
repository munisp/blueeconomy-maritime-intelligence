package isr

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// Modality identifies the sensor family one ISR detection originates from.
type Modality string

const (
	ModalityAIS      Modality = "AIS"
	ModalitySAR      Modality = "SAR"
	ModalityRF       Modality = "RF"
	ModalityAcoustic Modality = "ACOUSTIC"
	ModalityOptical  Modality = "OPTICAL"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var mmsiPattern = regexp.MustCompile(`^[0-9]{9}$`)
var sha256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// AISPayload carries one Automatic Identification System position report.
type AISPayload struct {
	MMSI        string  `json:"mmsi"`
	SpeedKnots  float64 `json:"speed_knots"`
	HeadingDeg  float64 `json:"heading_deg"`
	NavStatus   string  `json:"nav_status"`
	CallSign    string  `json:"call_sign,omitempty"`
	Destination string  `json:"destination,omitempty"`
}

// SARPayload carries one synthetic-aperture radar satellite detection.
type SARPayload struct {
	SceneRef    string  `json:"scene_ref"`
	Confidence  float64 `json:"confidence"`
	VesselClass string  `json:"vessel_class,omitempty"`
	LengthM     float64 `json:"length_m,omitempty"`
}

// RFPayload carries one radio-frequency direction-finding detection.
type RFPayload struct {
	FrequencyBand string  `json:"frequency_band"`
	BearingDeg    float64 `json:"bearing_deg"`
	SignalDBM     float64 `json:"signal_dbm,omitempty"`
	EmitterRef    string  `json:"emitter_ref,omitempty"`
}

// AcousticPayload carries one hydrophone/acoustic-signature detection.
type AcousticPayload struct {
	SignatureRef string  `json:"signature_ref"`
	Confidence   float64 `json:"confidence"`
	BearingDeg   float64 `json:"bearing_deg,omitempty"`
}

// DetectionBox is one normalised optical detection bounding box. All
// coordinates are fractions of the image dimensions in [0,1].
type DetectionBox struct {
	X          float64 `json:"x"`
	Y          float64 `json:"y"`
	Width      float64 `json:"width"`
	Height     float64 `json:"height"`
	Confidence float64 `json:"confidence"`
}

// OpticalPayload carries one electro-optical imagery detection set.
type OpticalPayload struct {
	ImageRef string         `json:"image_ref"`
	Boxes    []DetectionBox `json:"detection_boxes"`
}

// Detection is one validated multi-modal sensor detection admitted from an
// authorised, signature-verified feed source. Exactly one modality payload is
// present; Classification is mandatory and drives all downstream labelling.
type Detection struct {
	EventID        string           `json:"event_id"`
	SourceID       string           `json:"source_id"`
	SourceEventID  string           `json:"source_event_id"`
	Modality       Modality         `json:"modality"`
	Classification Classification   `json:"classification"`
	ObservedAt     time.Time        `json:"observed_at"`
	HasPosition    bool             `json:"has_position"`
	Latitude       float64          `json:"latitude,omitempty"`
	Longitude      float64          `json:"longitude,omitempty"`
	MMSI           string           `json:"mmsi,omitempty"`
	AIS            *AISPayload      `json:"ais,omitempty"`
	SAR            *SARPayload      `json:"sar,omitempty"`
	RF             *RFPayload       `json:"rf,omitempty"`
	Acoustic       *AcousticPayload `json:"acoustic,omitempty"`
	Optical        *OpticalPayload  `json:"optical,omitempty"`
	// CorrelationRefs link this detection to cross-workstream anomaly
	// identifiers (e.g. Workstream B ferries.telemetry or Workstream E
	// fisheries-EEZ anomaly IDs) consumed by security-operations'
	// cross-workstream-correlation rule.
	CorrelationRefs []string `json:"correlation_refs,omitempty"`
}

var approvedFrequencyBands = map[string]struct{}{
	"HF": {}, "VHF": {}, "UHF": {}, "L": {}, "S": {}, "C": {}, "X": {}, "KU": {}, "KA": {},
}

func isFinite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func validateUnitInterval(name string, value float64) error {
	if !isFinite(value) || value < 0 || value > 1 {
		return fmt.Errorf("%s must be a finite value within [0,1]", name)
	}
	return nil
}

func validateHeading(name string, value float64) error {
	if !isFinite(value) || value < 0 || value > 360 {
		return fmt.Errorf("%s must be a finite bearing within [0,360] degrees", name)
	}
	return nil
}

func validateCanonicalID(name, value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("%s must be a canonical identifier", name)
	}
	return nil
}

func (payload AISPayload) validate() error {
	if !mmsiPattern.MatchString(payload.MMSI) {
		return errors.New("ais.mmsi must be a 9-digit maritime mobile service identity")
	}
	if !isFinite(payload.SpeedKnots) || payload.SpeedKnots < 0 || payload.SpeedKnots > 102.2 {
		return errors.New("ais.speed_knots must be a finite value within [0,102.2]")
	}
	if err := validateHeading("ais.heading_deg", payload.HeadingDeg); err != nil {
		return err
	}
	if len(payload.NavStatus) > 64 || strings.TrimSpace(payload.NavStatus) != payload.NavStatus {
		return errors.New("ais.nav_status must be canonical text of at most 64 characters")
	}
	return nil
}

func (payload SARPayload) validate() error {
	if err := validateCanonicalID("sar.scene_ref", payload.SceneRef); err != nil {
		return err
	}
	if err := validateUnitInterval("sar.confidence", payload.Confidence); err != nil {
		return err
	}
	if payload.LengthM != 0 && (!isFinite(payload.LengthM) || payload.LengthM < 0 || payload.LengthM > 500) {
		return errors.New("sar.length_m must be a finite value within [0,500]")
	}
	return nil
}

func (payload RFPayload) validate() error {
	if _, ok := approvedFrequencyBands[strings.ToUpper(payload.FrequencyBand)]; !ok {
		return errors.New("rf.frequency_band is not an approved band")
	}
	return validateHeading("rf.bearing_deg", payload.BearingDeg)
}

func (payload AcousticPayload) validate() error {
	if err := validateCanonicalID("acoustic.signature_ref", payload.SignatureRef); err != nil {
		return err
	}
	return validateUnitInterval("acoustic.confidence", payload.Confidence)
}

func (payload OpticalPayload) validate() error {
	if err := validateCanonicalID("optical.image_ref", payload.ImageRef); err != nil {
		return err
	}
	if len(payload.Boxes) == 0 || len(payload.Boxes) > 64 {
		return errors.New("optical.detection_boxes must contain between 1 and 64 boxes")
	}
	for index, box := range payload.Boxes {
		for name, value := range map[string]float64{
			"x": box.X, "y": box.Y, "width": box.Width, "height": box.Height, "confidence": box.Confidence,
		} {
			if err := validateUnitInterval(fmt.Sprintf("optical.detection_boxes[%d].%s", index, name), value); err != nil {
				return err
			}
		}
		if box.X+box.Width > 1+1e-9 || box.Y+box.Height > 1+1e-9 {
			return fmt.Errorf("optical.detection_boxes[%d] exceeds the image bounds", index)
		}
	}
	return nil
}

// Validate enforces the multi-modal contract fail-closed: classification is
// mandatory, exactly one modality payload is present and that payload passes
// its per-modality validation. A detection without a position may still be
// admitted (e.g. a bearing-only RF fix) but can never seed a spatial track.
func (detection Detection) Validate() error {
	if err := validateCanonicalID("event_id", detection.EventID); err != nil {
		return err
	}
	if err := validateCanonicalID("source_id", detection.SourceID); err != nil {
		return err
	}
	if err := validateCanonicalID("source_event_id", detection.SourceEventID); err != nil {
		return err
	}
	if _, err := ParseClassification(string(detection.Classification)); err != nil {
		return err
	}
	if detection.ObservedAt.IsZero() {
		return errors.New("observed_at must be RFC3339")
	}
	if detection.HasPosition {
		if !isFinite(detection.Latitude) || detection.Latitude < -90 || detection.Latitude > 90 ||
			!isFinite(detection.Longitude) || detection.Longitude < -180 || detection.Longitude > 180 {
			return errors.New("latitude/longitude must be finite WGS-84 coordinates")
		}
	}
	if detection.MMSI != "" && !mmsiPattern.MatchString(detection.MMSI) {
		return errors.New("mmsi must be a 9-digit identifier when present")
	}
	present := 0
	var modalityErr error
	switch detection.Modality {
	case ModalityAIS:
		if detection.AIS != nil {
			present++
			modalityErr = detection.AIS.validate()
			if modalityErr == nil && detection.MMSI == "" {
				detection.MMSI = detection.AIS.MMSI
			}
		}
	case ModalitySAR:
		if detection.SAR != nil {
			present++
			modalityErr = detection.SAR.validate()
		}
	case ModalityRF:
		if detection.RF != nil {
			present++
			modalityErr = detection.RF.validate()
		}
	case ModalityAcoustic:
		if detection.Acoustic != nil {
			present++
			modalityErr = detection.Acoustic.validate()
		}
	case ModalityOptical:
		if detection.Optical != nil {
			present++
			modalityErr = detection.Optical.validate()
		}
	default:
		return errors.New("modality must be one of AIS, SAR, RF, ACOUSTIC, OPTICAL")
	}
	if present == 0 {
		return fmt.Errorf("%s modality payload is required", detection.Modality)
	}
	if modalityErr != nil {
		return modalityErr
	}
	for _, other := range []struct {
		name    string
		present bool
	}{
		{"ais", detection.AIS != nil}, {"sar", detection.SAR != nil}, {"rf", detection.RF != nil},
		{"acoustic", detection.Acoustic != nil}, {"optical", detection.Optical != nil},
	} {
		if other.present && !strings.EqualFold(other.name, string(detection.Modality)) {
			return fmt.Errorf("%s payload must not accompany modality %s", other.name, detection.Modality)
		}
	}
	for _, ref := range detection.CorrelationRefs {
		if err := validateCanonicalID("correlation_refs", ref); err != nil {
			return err
		}
	}
	if len(detection.CorrelationRefs) > 32 {
		return errors.New("correlation_refs must contain at most 32 references")
	}
	return nil
}
