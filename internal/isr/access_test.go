package isr

import "testing"

// MI-1 supporting coverage: IsReadOnly is the middleware-level fail-closed
// check — a principal without a recognized mutating role is read-only, and
// unrecognized roles never acquire mutation rights by absence of a deny-list.
func TestIsReadOnlyFailsClosedOnUnrecognizedRoles(t *testing.T) {
	readOnlyCases := map[string]Principal{
		"no roles":           {Subject: "sub-1", Roles: map[string]struct{}{}, Clearance: ClassificationSecret},
		"garbage role":       {Subject: "sub-2", Roles: map[string]struct{}{"garbage-role": {}}, Clearance: ClassificationSecret},
		"typo role":          {Subject: "sub-3", Roles: map[string]struct{}{"isr-adminn": {}}, Clearance: ClassificationSecret},
		"case-variant role":  {Subject: "sub-4", Roles: map[string]struct{}{"ISR-ADMIN": {}}, Clearance: ClassificationSecret},
		"legacy read-only":   {Subject: "sub-5", Roles: map[string]struct{}{RoleDefenceHQObserver: {}}, Clearance: ClassificationSecret},
		"observer plus typo": {Subject: "sub-6", Roles: map[string]struct{}{RoleONSAObserver: {}, "isr-analyzt": {}}, Clearance: ClassificationSecret},
		"insurer-aggregator": {Subject: "sub-7", Roles: map[string]struct{}{RoleInsurerAggregator: {}}, Clearance: ClassificationSecret},
		"auditor":            {Subject: "sub-8", Roles: map[string]struct{}{RoleAuditor: {}}, Clearance: ClassificationSecret},
	}
	for name, principal := range readOnlyCases {
		if !principal.IsReadOnly() {
			t.Errorf("%s must be read-only", name)
		}
	}
	mutating := map[string]string{
		"isr-admin":         RoleISRAdmin,
		"isr-feed-ingest":   RoleISRFeedIngest,
		"isr-analyst":       RoleISRAnalyst,
		"isr-watch-officer": RoleISRWatchOfficer,
		"isr-adjudicator":   RoleISRAdjudicator,
		"nimasa-officer":    RoleNIMASAOfficer,
		"nn-officer":        RoleNNOfficer,
		"marine-police":     RoleMarinePolice,
		"fleet-operator":    RoleFleetOperator,
	}
	for name, role := range mutating {
		principal := Principal{Subject: "sub", Roles: map[string]struct{}{role: {}}, Clearance: ClassificationUnclassified}
		if principal.IsReadOnly() {
			t.Errorf("%s (%s) must not be read-only", name, role)
		}
	}
	// A recognized mutating role alongside garbage roles still mutates.
	principal := Principal{Subject: "sub", Roles: map[string]struct{}{RoleISRAnalyst: {}, "garbage": {}}, Clearance: ClassificationUnclassified}
	if principal.IsReadOnly() {
		t.Error("recognized mutating role must dominate unrecognized roles")
	}
}

// Track reads stay role- and clearance-gated; the insurer-aggregator is
// denied tracks but admitted to outcome aggregates.
func TestTrackAndAggregateReadGates(t *testing.T) {
	secretInsurer := Principal{Subject: "ins-1", Roles: map[string]struct{}{RoleInsurerAggregator: {}}, Clearance: ClassificationSecret}
	if err := secretInsurer.CanReadTracks(ClassificationUnclassified); err != ErrForbidden {
		t.Fatalf("insurer-aggregator must be denied tracks, got %v", err)
	}
	if err := secretInsurer.CanReadOutcomeAggregates(); err != nil {
		t.Fatalf("insurer-aggregator must read outcome aggregates, got %v", err)
	}
	reader := Principal{Subject: "nn-1", Roles: map[string]struct{}{RoleNNOfficer: {}}, Clearance: ClassificationRestricted}
	if err := reader.CanReadTracks(ClassificationRestricted); err != nil {
		t.Fatal(err)
	}
	if err := reader.CanReadTracks(ClassificationConfidential); err != ErrForbidden {
		t.Fatalf("clearance must cover the record label, got %v", err)
	}
	unknown := Principal{Subject: "x", Roles: map[string]struct{}{"garbage": {}}, Clearance: ClassificationSecret}
	if err := unknown.CanReadTracks(ClassificationUnclassified); err != ErrForbidden {
		t.Fatalf("unknown role must be denied tracks, got %v", err)
	}
	if err := unknown.CanReadOutcomeAggregates(); err != ErrForbidden {
		t.Fatalf("unknown role must be denied aggregates, got %v", err)
	}
}

// SAR/Yaoundé read gates are role-gated fail-closed.
func TestSARAndYaoundeReadGates(t *testing.T) {
	observer := Principal{Subject: "s1", Roles: map[string]struct{}{RoleSARObserver: {}}, Clearance: ClassificationRestricted}
	if err := observer.CanReadSAR(ClassificationRestricted); err != nil {
		t.Fatal(err)
	}
	if err := observer.CanReadSAR(ClassificationConfidential); err != ErrForbidden {
		t.Fatalf("SAR clearance gate failed: %v", err)
	}
	if err := observer.CanReadYaounde(ClassificationUnclassified); err != ErrForbidden {
		t.Fatalf("sar-observer must not read yaounde state: %v", err)
	}
	releaser := Principal{Subject: "y1", Roles: map[string]struct{}{RoleYaoundeReleaser: {}}, Clearance: ClassificationSecret}
	if err := releaser.CanReadYaounde(ClassificationSecret); err != nil {
		t.Fatal(err)
	}
	if err := releaser.CanReadSAR(ClassificationUnclassified); err != ErrForbidden {
		t.Fatalf("yaounde roles must not read SAR cases: %v", err)
	}
	unknown := Principal{Subject: "x", Roles: map[string]struct{}{"garbage": {}}, Clearance: ClassificationSecret}
	if err := unknown.CanReadSAR(ClassificationUnclassified); err != ErrForbidden {
		t.Fatalf("unknown role must be denied SAR reads, got %v", err)
	}
	if err := unknown.CanReadYaounde(ClassificationUnclassified); err != ErrForbidden {
		t.Fatalf("unknown role must be denied yaounde reads, got %v", err)
	}
}
