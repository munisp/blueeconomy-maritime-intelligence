package geo

import (
	"testing"
)

func position(t *testing.T, lat, lon float64) Position {
	t.Helper()
	p, err := NewPosition(lat, lon)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func squareZone(t *testing.T) Zone {
	t.Helper()
	zone, err := NewZone("zone-1", ZoneKindRestricted, []Position{
		{Latitude: 0, Longitude: 0}, {Latitude: 0, Longitude: 4},
		{Latitude: 4, Longitude: 4}, {Latitude: 4, Longitude: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	return zone
}

func TestContainsInteriorExteriorBoundary(t *testing.T) {
	zone := squareZone(t)
	if !zone.Contains(position(t, 2, 2)) {
		t.Fatal("interior point must be inside")
	}
	if zone.Contains(position(t, 5, 2)) {
		t.Fatal("exterior point reported inside")
	}
	if zone.Contains(position(t, 2, -0.5)) {
		t.Fatal("exterior point reported inside")
	}
	// Boundary-inclusive: edge and vertex points are inside (fail-closed for
	// alerting), matching geo.rs.
	if !zone.Contains(position(t, 0, 2)) {
		t.Fatal("edge point must be inside")
	}
	if !zone.Contains(position(t, 0, 0)) {
		t.Fatal("vertex point must be inside")
	}
}

func TestZoneValidationFailsClosed(t *testing.T) {
	if _, err := NewZone("bad zone", ZoneKindRestricted, []Position{{0, 0}, {0, 1}, {1, 1}}); err == nil {
		t.Fatal("invalid zone_id accepted")
	}
	if _, err := NewZone("zone-2", ZoneKindRestricted, []Position{{0, 0}, {0, 1}}); err == nil {
		t.Fatal("two-vertex polygon accepted")
	}
	if _, err := NewZone("zone-3", "unknown", []Position{{0, 0}, {0, 1}, {1, 1}}); err == nil {
		t.Fatal("unknown zone kind accepted")
	}
	repeated := []Position{{0, 0}, {0, 0}, {1, 1}}
	if _, err := NewZone("zone-4", ZoneKindEEZ, repeated); err == nil {
		t.Fatal("repeated consecutive vertices accepted")
	}
	if _, err := NewPosition(91, 0); err == nil {
		t.Fatal("latitude above 90 accepted")
	}
	if _, err := NewPosition(0, 181); err == nil {
		t.Fatal("longitude above 180 accepted")
	}
	if _, err := NewPosition(0, nan()); err == nil {
		t.Fatal("NaN longitude accepted")
	}
}

func nan() float64 {
	zero := 0.0
	return zero / zero
}

func TestDistanceMeters(t *testing.T) {
	a := position(t, 0, 0)
	b := position(t, 1, 0)
	distance := DistanceMeters(a, b)
	if distance < 111_000 || distance > 112_000 {
		t.Fatalf("one degree latitude must be about 111.32 km, got %.0f m", distance)
	}
	if DistanceMeters(a, a) != 0 {
		t.Fatal("self distance must be zero")
	}
}

func TestZonesContaining(t *testing.T) {
	zone := squareZone(t)
	if overlaps := ZonesContaining(position(t, 2, 2), []Zone{zone}); len(overlaps) != 1 {
		t.Fatal("expected one overlap")
	}
	if overlaps := ZonesContaining(position(t, 9, 9), []Zone{zone}); len(overlaps) != 0 {
		t.Fatal("expected no overlap")
	}
}
