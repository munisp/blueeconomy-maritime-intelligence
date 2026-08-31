// Package geo ports the boundary-inclusive polygon containment approach from
// blueeconomy-waterway-safety/src/geo.rs to Go for restricted-zone and EEZ
// analytics. All constructors validate fail-closed; a position lying exactly
// on a zone boundary is treated as inside so alerting never misses a
// boundary crossing.
package geo

import (
	"errors"
	"math"
	"regexp"
)

const (
	// MaxZoneVertices bounds polygon complexity for deterministic evaluation.
	MaxZoneVertices         = 10_000
	boundaryCrossTolerance  = 1e-12
	metersPerDegreeLatitude = 111_320.0
)

var zoneIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)

// Position is one validated WGS-84 position in degrees.
type Position struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// NewPosition validates coordinates fail-closed.
func NewPosition(latitude, longitude float64) (Position, error) {
	if math.IsNaN(latitude) || math.IsInf(latitude, 0) || latitude < -90 || latitude > 90 ||
		math.IsNaN(longitude) || math.IsInf(longitude, 0) || longitude < -180 || longitude > 180 {
		return Position{}, errors.New("coordinates must be finite with latitude in [-90,90] and longitude in [-180,180]")
	}
	return Position{Latitude: latitude, Longitude: longitude}, nil
}

// DistanceMeters approximates the ground distance between two positions with
// an equirectangular projection, accurate enough for correlation windows.
func DistanceMeters(a, b Position) float64 {
	dLat := (b.Latitude - a.Latitude) * metersPerDegreeLatitude
	midLat := (a.Latitude + b.Latitude) / 2 * math.Pi / 180
	cosLat := math.Cos(midLat)
	if math.Abs(cosLat) < 1e-3 {
		cosLat = math.Copysign(1e-3, cosLat)
	}
	dLon := (b.Longitude - a.Longitude) * metersPerDegreeLatitude * cosLat
	return math.Hypot(dLat, dLon)
}

// ZoneKind classifies a zone polygon.
type ZoneKind string

const (
	ZoneKindEEZ        ZoneKind = "eez"
	ZoneKindRestricted ZoneKind = "restricted"
)

// Zone is one validated EEZ or restricted-zone polygon.
type Zone struct {
	ZoneID   string     `json:"zone_id"`
	ZoneKind ZoneKind   `json:"zone_kind"`
	Vertices []Position `json:"vertices"`
}

// NewZone validates the polygon fail-closed: 3..MaxZoneVertices vertices, no
// repeated consecutive vertices, canonical zone identifier.
func NewZone(zoneID string, kind ZoneKind, vertices []Position) (Zone, error) {
	if !zoneIDPattern.MatchString(zoneID) {
		return Zone{}, errors.New("zone_id must be a canonical identifier")
	}
	if kind != ZoneKindEEZ && kind != ZoneKindRestricted {
		return Zone{}, errors.New("zone_kind must be eez or restricted")
	}
	if len(vertices) < 3 || len(vertices) > MaxZoneVertices {
		return Zone{}, errors.New("zone polygon must contain between 3 and 10000 vertices")
	}
	for index := range vertices {
		if _, err := NewPosition(vertices[index].Latitude, vertices[index].Longitude); err != nil {
			return Zone{}, err
		}
		next := vertices[(index+1)%len(vertices)]
		if vertices[index] == next {
			return Zone{}, errors.New("zone polygon must not repeat consecutive vertices")
		}
	}
	copied := make([]Position, len(vertices))
	copy(copied, vertices)
	return Zone{ZoneID: zoneID, ZoneKind: kind, Vertices: copied}, nil
}

// Contains is the boundary-inclusive even-odd containment test ported from
// geo.rs: a position exactly on an edge or vertex is inside the zone.
func (zone Zone) Contains(position Position) bool {
	count := len(zone.Vertices)
	if count < 3 {
		return false
	}
	for index := 0; index < count; index++ {
		if pointOnSegment(position, zone.Vertices[index], zone.Vertices[(index+1)%count]) {
			return true
		}
	}
	px, py := position.Longitude, position.Latitude
	inside := false
	for index := 0; index < count; index++ {
		start := zone.Vertices[index]
		end := zone.Vertices[(index+1)%count]
		ax, ay := start.Longitude, start.Latitude
		bx, by := end.Longitude, end.Latitude
		if (ay > py) != (by > py) {
			intersectionX := ax + (py-ay)*(bx-ax)/(by-ay)
			if intersectionX > px {
				inside = !inside
			}
		}
	}
	return inside
}

func pointOnSegment(position, start, end Position) bool {
	px, py := position.Longitude, position.Latitude
	ax, ay := start.Longitude, start.Latitude
	bx, by := end.Longitude, end.Latitude
	dx := bx - ax
	dy := by - ay
	cross := dx*(py-ay) - dy*(px-ax)
	scale := math.Max(dx*dx+dy*dy, 1.0)
	if math.Abs(cross) > boundaryCrossTolerance*scale {
		return false
	}
	return (px-ax)*dx+(py-ay)*dy >= 0 && (px-bx)*dx+(py-by)*dy <= 0
}

// ZonesContaining returns every zone containing the position; an empty result
// means the position is clear of all supplied zones.
func ZonesContaining(position Position, zones []Zone) []Zone {
	overlaps := make([]Zone, 0, len(zones))
	for _, zone := range zones {
		if zone.Contains(position) {
			overlaps = append(overlaps, zone)
		}
	}
	return overlaps
}
