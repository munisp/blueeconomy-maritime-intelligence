package isr

import "testing"

// MI-1 regression: IsReadOnly must fail closed. A token carrying a garbage,
// mistyped or absent role previously failed OPEN (mutations allowed) because
// IsReadOnly returned false for any unrecognized role.
func TestIsReadOnlyFailsClosedOnUnrecognizedRoles(t *testing.T) {
	readOnlyCases := map[string]Principal{
		"no roles":           {Subject: "u-none", Roles: map[string]struct{}{}},
		"garbage role":       {Subject: "u-garbage", Roles: map[string]struct{}{"garbage-role": {}}},
		"typo role":          {Subject: "u-typo", Roles: map[string]struct{}{"isr-adminn": {}}},
		"case-variant role":  {Subject: "u-case", Roles: map[string]struct{}{"ISR-ADMIN": {}}},
		"legacy read-only":   {Subject: "u-obs", Roles: map[string]struct{}{RoleDefenceHQObserver: {}}},
		"observer plus typo": {Subject: "u-mix", Roles: map[string]struct{}{RoleONSAObserver: {}, "isr-analys": {}}},
		"insurer-aggregator": {Subject: "u-ins", Roles: map[string]struct{}{RoleInsurerAggregator: {}}},
		"auditor":            {Subject: "u-aud", Roles: map[string]struct{}{RoleAuditor: {}}},
	}
	for name, principal := range readOnlyCases {
		if !principal.IsReadOnly() {
			t.Fatalf("%s: principal must be read-only (fail-closed)", name)
		}
	}
	mutatingRoles := []string{
		RoleNIMASAOfficer, RoleNNOfficer, RoleMarinePolice, RoleFleetOperator,
		RoleISRAdmin, RoleISRFeedIngest, RoleISRAnalyst, RoleISRWatchOfficer, RoleISRAdjudicator,
	}
	for _, role := range mutatingRoles {
		principal := Principal{Subject: "u-" + role, Roles: map[string]struct{}{role: {}}}
		if principal.IsReadOnly() {
			t.Fatalf("recognized mutating role %s must not be read-only", role)
		}
	}
	// A garbage role alongside a recognized mutating role does not widen or
	// narrow anything: the recognized role governs.
	principal := Principal{Subject: "u-mixed", Roles: map[string]struct{}{RoleISRAnalyst: {}, "garbage": {}}}
	if principal.IsReadOnly() {
		t.Fatal("recognized mutating role must govern over garbage role")
	}
}

// MI-1 regression: read-side role model is unchanged for existing roles and
// fails closed for unknown roles (deny reads beyond the public floor).
func TestReadAccessUnchangedAndFailClosed(t *testing.T) {
	trackReaders := []string{
		RoleNIMASAOfficer, RoleDefenceHQObserver, RoleNNOfficer, RoleONSAObserver,
		RoleMarinePolice, RoleFleetOperator, RoleAuditor, RoleISRAnalyst, RoleISRWatchOfficer,
	}
	for _, role := range trackReaders {
		principal := Principal{Subject: "u", Roles: map[string]struct{}{role: {}}, Clearance: ClassificationSecret}
		if err := principal.CanReadTracks(ClassificationSecret); err != nil {
			t.Fatalf("role %s must retain track read access: %v", role, err)
		}
		if err := principal.CanReadOutcomeAggregates(); err != nil {
			t.Fatalf("role %s must retain aggregate read access: %v", role, err)
		}
	}
	// Unknown roles are denied track reads regardless of clearance.
	for _, role := range []string{"garbage-role", "isr-adminn", RoleISRAdmin, RoleISRFeedIngest} {
		principal := Principal{Subject: "u", Roles: map[string]struct{}{role: {}}, Clearance: ClassificationSecret}
		if err := principal.CanReadTracks(ClassificationUnclassified); err != ErrForbidden {
			t.Fatalf("role %q must be denied track reads, got %v", role, err)
		}
	}
	// Insurer-aggregator keeps its aggregate-only access; unknown roles get nothing.
	insurer := Principal{Subject: "u", Roles: map[string]struct{}{RoleInsurerAggregator: {}}, Clearance: ClassificationSecret}
	if err := insurer.CanReadOutcomeAggregates(); err != nil {
		t.Fatalf("insurer-aggregator must retain aggregate read: %v", err)
	}
	if err := insurer.CanReadTracks(ClassificationUnclassified); err != ErrForbidden {
		t.Fatal("insurer-aggregator must remain denied from tracks")
	}
	unknown := Principal{Subject: "u", Roles: map[string]struct{}{"garbage": {}}, Clearance: ClassificationSecret}
	if err := unknown.CanReadOutcomeAggregates(); err != ErrForbidden {
		t.Fatal("unknown role must be denied outcome aggregates")
	}
}

func TestHasAnyRole(t *testing.T) {
	principal := Principal{Subject: "u", Roles: map[string]struct{}{RoleISRAnalyst: {}}}
	if !principal.HasAnyRole(RoleISRAnalyst, RoleISRWatchOfficer) {
		t.Fatal("HasAnyRole must match one held role")
	}
	if principal.HasAnyRole(RoleISRAdmin, RoleISRAdjudicator) {
		t.Fatal("HasAnyRole must fail closed when no role matches")
	}
	if principal.HasAnyRole() {
		t.Fatal("HasAnyRole with no required roles must fail closed")
	}
}
