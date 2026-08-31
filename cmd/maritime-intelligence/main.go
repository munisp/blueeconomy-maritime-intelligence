package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	tigerbeetle "github.com/tigerbeetle/tigerbeetle-go"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/geo"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/ledger"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/server"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/telemetry"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/tracks"
)

func main() {
	if err := run(); err != nil {
		log.Printf("maritime-intelligence: %v", err)
		os.Exit(1)
	}
}

// latencyAdapter reports fusion detection latency to the telemetry pipeline.
type latencyAdapter struct{ telemetry *telemetry.Telemetry }

func (adapter latencyAdapter) RecordDetectionLatency(ctx context.Context, kind tracks.AnomalyKind, seconds float64) {
	if adapter.telemetry != nil {
		adapter.telemetry.RecordDetectionLatency(ctx, string(kind), seconds)
	}
}

// loadFusionZones reads the restricted/EEZ zone set from ISR_ZONES_FILE. An
// absent file means no zones (rendezvous/speed rules still run); a malformed
// file fails closed.
func loadFusionZones(path string) ([]geo.Zone, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read ISR_ZONES_FILE: %w", err)
	}
	var zones []geo.Zone
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&zones); err != nil {
		return nil, fmt.Errorf("ISR_ZONES_FILE must be a JSON array of zones: %w", err)
	}
	for _, zone := range zones {
		if _, err := geo.NewZone(zone.ZoneID, zone.ZoneKind, zone.Vertices); err != nil {
			return nil, fmt.Errorf("ISR_ZONES_FILE zone %q: %w", zone.ZoneID, err)
		}
	}
	return zones, nil
}

// loadOutcomeService builds the TigerBeetle outcome service. Fail-closed:
// when TIGERBEETLE_ADDRESS is set the connection must succeed; when unset the
// outcome routes answer 503 (never silently enabled).
func loadOutcomeService(ctx context.Context) (*ledger.Service, func(), error) {
	address := strings.TrimSpace(os.Getenv("TIGERBEETLE_ADDRESS"))
	if address == "" {
		log.Printf("maritime-intelligence: TIGERBEETLE_ADDRESS unset; outcome ledger routes disabled (503)")
		return nil, func() {}, nil
	}
	clusterID := tigerbeetle.ToUint128(0)
	if value := strings.TrimSpace(os.Getenv("TIGERBEETLE_CLUSTER_ID")); value != "" {
		var parsed uint64
		if _, err := fmt.Sscanf(value, "%d", &parsed); err != nil || parsed == 0 {
			return nil, nil, errors.New("TIGERBEETLE_CLUSTER_ID must be a positive integer when set")
		}
		clusterID = tigerbeetle.ToUint128(parsed)
	}
	client, err := tigerbeetle.NewClient(clusterID, []string{address})
	if err != nil {
		return nil, nil, fmt.Errorf("connect TigerBeetle: %w", err)
	}
	_ = ctx
	service, err := ledger.New(client, 1, 1)
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	if err := service.EnsureAccounts(); err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("provision outcome accounts: %w", err)
	}
	return service, func() { client.Close() }, nil
}

func run() error {
	databaseURL := requiredEnv("DATABASE_URL")
	migrationPaths := requiredEnv("MIGRATION_PATH")
	port := requiredEnv("PORT")
	authConfig, err := server.LoadAuthConfig(os.Getenv)
	if err != nil {
		return err
	}
	authenticator, err := server.NewAuthenticator(authConfig)
	if err != nil {
		return err
	}
	migrationPathsList := strings.Split(migrationPaths, ",")
	if len(migrationPathsList) == 0 {
		return errors.New("MIGRATION_PATH must contain at least one path")
	}
	migrations := make([][]byte, 0, len(migrationPathsList))
	for _, migrationPath := range migrationPathsList {
		migrationPath = strings.TrimSpace(migrationPath)
		if migrationPath == "" {
			return errors.New("MIGRATION_PATH contains an empty path")
		}
		migration, err := os.ReadFile(filepath.Clean(migrationPath))
		if err != nil {
			return fmt.Errorf("read migration %q: %w", migrationPath, err)
		}
		migrations = append(migrations, migration)
	}
	telemetryConfig, err := telemetry.LoadConfig("blueeconomy-maritime-intelligence")
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	telemetryPipeline, err := telemetry.Setup(ctx, telemetryConfig)
	if err != nil {
		return fmt.Errorf("telemetry setup: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = telemetryPipeline.Shutdown(shutdownCtx)
	}()
	store, err := incident.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	for index, migration := range migrations {
		if err := store.Exec(ctx, string(migration)); err != nil {
			return fmt.Errorf("apply migration %d: %w", index+1, err)
		}
	}
	zones, err := loadFusionZones(os.Getenv("ISR_ZONES_FILE"))
	if err != nil {
		return err
	}
	fusion, err := tracks.NewEngine(tracks.DefaultConfig(), zones, latencyAdapter{telemetry: telemetryPipeline}, nil, nil)
	if err != nil {
		return fmt.Errorf("fusion engine: %w", err)
	}
	trackStore := tracks.NewStore(store.Pool())
	// Rebuild fusion engine state before serving: replay every persisted
	// track association (in observation order) through Engine.Replay so track
	// identities, points and rule bookkeeping survive a restart and
	// GET /v1/isr/tracks serves the pre-restart state immediately. New track
	// IDs are UUID-based, so a post-restart engine can never collide with a
	// persisted track identity. Fail-closed: a replay failure aborts startup
	// rather than serving an amnesiac or corrupted track view.
	if err := replayTrackAssociations(ctx, trackStore, fusion); err != nil {
		return err
	}
	outcomeService, closeTigerBeetle, err := loadOutcomeService(ctx)
	if err != nil {
		return err
	}
	defer closeTigerBeetle()
	scanInterval, scanEnabled, err := darkVesselScanInterval(os.Getenv("ISR_DARK_VESSEL_SCAN_INTERVAL"))
	if err != nil {
		return err
	}
	if scanEnabled {
		scanner, err := tracks.NewDarkVesselScanner(fusion, trackStore, scanInterval, nil)
		if err != nil {
			return fmt.Errorf("dark-vessel scanner: %w", err)
		}
		go func() {
			if err := scanner.Run(ctx); err != nil {
				log.Printf("maritime-intelligence: dark-vessel scanner stopped: %v", err)
			}
		}()
		log.Printf("maritime-intelligence: dark-vessel scanner every %s", scanInterval)
	} else {
		log.Printf("maritime-intelligence: dark-vessel scanner disabled (ISR_DARK_VESSEL_SCAN_INTERVAL=0)")
	}
	isrDeps := &server.ISRDeps{
		ISRStore:        isr.NewStore(store.Pool()),
		TrackStore:      trackStore,
		Fusion:          fusion,
		FusionErrorHook: telemetryPipeline.RecordFusionIngestError,
	}
	if outcomeService != nil {
		outcomeStore, err := ledger.NewOutcomeStore(store.Pool(), outcomeService)
		if err != nil {
			return err
		}
		isrDeps.Outcomes = outcomeStore
	}
	handler := telemetryPipeline.Middleware(server.New(server.Config{
		Store:         store,
		ISR:           isrDeps,
		Authenticator: authenticator,
		ReadyzCheck: func(ctx context.Context) error {
			return store.Pool().Ping(ctx)
		},
		Metrics: telemetryPipeline.MetricsHandler(),
	}))
	httpServer := &http.Server{
		Addr: ":" + port, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	if telemetryConfig.Enabled {
		log.Printf("maritime-intelligence listening on :%s (auth=%s, OTLP traces to %s, metrics on GET /metrics)", port, authConfig.Mode, telemetryConfig.Endpoint)
	} else {
		log.Printf("maritime-intelligence listening on :%s (auth=%s, tracing disabled, metrics on GET /metrics)", port, authConfig.Mode)
	}
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// replayTrackAssociations rebuilds fusion engine state from the persisted
// association audit before the server accepts traffic. Every association is
// replayed with its original persisted track identity; a decode or replay
// failure aborts startup fail-closed.
func replayTrackAssociations(ctx context.Context, trackStore *tracks.Store, fusion *tracks.Engine) error {
	replays, err := trackStore.ListAssociationsForReplay(ctx)
	if err != nil {
		return fmt.Errorf("reload track associations: %w", err)
	}
	for _, replay := range replays {
		detection, err := isr.DecodeDetection(replay.Payload)
		if err != nil {
			return fmt.Errorf("reload track association %s: retained detection undecodable: %w", replay.TrackID, err)
		}
		if err := fusion.Replay(replay.TrackID, detection); err != nil {
			return fmt.Errorf("replay track association %s: %w", replay.TrackID, err)
		}
	}
	if len(replays) > 0 {
		log.Printf("maritime-intelligence: restored %d track associations into %d fused tracks", len(replays), len(fusion.Tracks()))
	}
	return nil
}

// darkVesselScanInterval parses ISR_DARK_VESSEL_SCAN_INTERVAL. Unset selects
// the default; the explicit value "0" is the only way to disable the scanner;
// anything else that is not a positive duration fails closed at startup.
func darkVesselScanInterval(value string) (time.Duration, bool, error) {
	const defaultInterval = time.Minute
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultInterval, true, nil
	}
	if value == "0" {
		return 0, false, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, false, fmt.Errorf("ISR_DARK_VESSEL_SCAN_INTERVAL must be a positive duration or 0 to disable: %q", value)
	}
	return parsed, true, nil
}

func requiredEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s must be set", name)
	}
	return value
}
