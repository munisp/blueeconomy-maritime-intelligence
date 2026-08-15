//go:build integration

package incident

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOutboxLeaseLifecycleAgainstPostgres(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("DATABASE_URL is required for the integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	migrationPath := os.Getenv("MIGRATION_PATH")
	for _, path := range splitNonEmpty(migrationPath) {
		migration, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if execErr := store.Exec(ctx, string(migration)); execErr != nil {
			t.Fatal(execErr)
		}
	}
	incidentID := "outbox-integration-" + uuid.NewString()
	sourceEventID := "outbox-source-" + uuid.NewString()
	defer func() {
		_, _ = store.pool.Exec(context.Background(), "DELETE FROM maritime_incidents WHERE incident_id = $1", incidentID)
	}()
	created, err := store.Create(ctx, CreateRequest{
		IncidentID: incidentID, SourceEventID: sourceEventID, Category: "DISTRESS", Severity: "HIGH",
		Title: "outbox integration", Description: "real PostgreSQL lease verification",
		OccurredAt: time.Now().UTC(), CreatedBy: "integration-operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.IncidentID != incidentID {
		t.Fatalf("unexpected incident: %+v", created)
	}
	event, err := store.ClaimOutbox(ctx, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if event.IncidentID != incidentID || event.Attempts != 1 || event.EventType != "incident.created" {
		t.Fatalf("unexpected claim: %+v", event)
	}
	if err := store.MarkOutboxPublished(ctx, event.EventID, "worker-b"); !errors.Is(err, ErrOutboxOwnership) {
		t.Fatalf("wrong worker publish was not rejected: %v", err)
	}
	if err := store.MarkOutboxFailed(ctx, event.EventID, "worker-a", "downstream unavailable", time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimOutbox(ctx, "worker-b", time.Minute); !errors.Is(err, ErrNoPendingOutbox) {
		t.Fatalf("future retry was claimable: %v", err)
	}
	if _, err := store.pool.Exec(ctx, "UPDATE maritime_incident_outbox SET available_at = now() WHERE event_id = $1", event.EventID); err != nil {
		t.Fatal(err)
	}
	redelivered, err := store.ClaimOutbox(ctx, "worker-b", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if redelivered.EventID != event.EventID || redelivered.Attempts != 2 {
		t.Fatalf("unexpected redelivery: %+v", redelivered)
	}
	if err := store.MarkOutboxPublished(ctx, redelivered.EventID, "worker-b"); err != nil {
		t.Fatal(err)
	}
	var published bool
	if err := store.pool.QueryRow(ctx, "SELECT published_at IS NOT NULL FROM maritime_incident_outbox WHERE event_id = $1", event.EventID).Scan(&published); err != nil {
		t.Fatal(err)
	}
	if !published {
		t.Fatal("event was not marked published")
	}
}

func splitNonEmpty(value string) []string {
	var result []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
