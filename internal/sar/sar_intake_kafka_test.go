//go:build kafkaintegration

package sar

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/envelope"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

// brokerEnv returns the shared broker/database test environment.
func brokerEnv(t *testing.T) (context.Context, *pgxpool.Pool, []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	brokers := strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
	if len(brokers) == 0 || brokers[0] == "" {
		t.Fatal("KAFKA_BROKERS is required")
	}
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	migrateOnce.Do(func() {
		for _, migrationPath := range strings.Split(os.Getenv("MIGRATION_PATH"), ",") {
			migration, readErr := os.ReadFile(filepath.Clean(strings.TrimSpace(migrationPath)))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if _, execErr := pool.Exec(context.Background(), string(migration)); execErr != nil {
				t.Fatalf("migration %s: %v", migrationPath, execErr)
			}
		}
	})
	t.Cleanup(pool.Close)
	return ctx, pool, brokers
}

func ensureTopic(t *testing.T, brokers []string, topic string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := kafka.DialContext(ctx, "tcp", brokers[0])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.CreateTopics(kafka.TopicConfig{Topic: topic, NumPartitions: 1, ReplicationFactor: 1}); err != nil {
		t.Logf("create topic %s: %v (may already exist)", topic, err)
	}
}

// TestWaterwayIntakeOverKafka produces a producer-conformant signed batch to
// ferries.telemetry.v1, consumes it with a real consumer group, admits the
// safety event through signed feed admission, opens the SAR case and then
// round-trips the emitted maritime.sar.v1 envelope through the broker with
// signature verification (the contracts convention).
func TestWaterwayIntakeOverKafka(t *testing.T) {
	ctx, pool, brokers := brokerEnv(t)
	// Unique topics per run: fresh consumer groups read from the first
	// offset, so shared topics would replay earlier runs' records.
	waterwayTopic := fmt.Sprintf("ferries.telemetry.v1.it%d", time.Now().UnixNano())
	sarTopic := fmt.Sprintf("maritime.sar.v1.it%d", time.Now().UnixNano())
	ensureTopic(t, brokers, waterwayTopic)
	ensureTopic(t, brokers, sarTopic)

	// Fleet key (waterway producer) and intake key.
	fleetPub, fleetPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intakePub, intakePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := provenance.ParseDirectory([]byte(`{"waterway-safety-1":"` + base64.RawURLEncoding.EncodeToString(fleetPub) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := provenance.NewSigner("sar-intake-1", intakePriv)
	if err != nil {
		t.Fatal(err)
	}

	// Register the intake as an ACTIVE SAR feed source.
	incidents := incident.NewStore(pool)
	if err := incidents.RegisterFeedSource(ctx, incident.FeedSourceRegistration{
		SourceID: "sar-intake-1", SourceKind: "SAR", Authority: "local-authority",
		PublicKey: intakePub, RegisteredBy: "registrar-it",
	}); err != nil {
		t.Fatal(err)
	}
	if err := incidents.ActivateFeedSource(ctx, incident.FeedSourceActivation{SourceID: "sar-intake-1", ActivatedBy: "activator-it"}); err != nil {
		t.Fatal(err)
	}

	cases := NewStore(pool).WithSigner(signer)
	processor := &IntakeProcessor{Incidents: incidents, Cases: cases, Directory: directory, Signer: signer, SourceID: "sar-intake-1", WaterwayTopic: waterwayTopic}
	if err := processor.Validate(); err != nil {
		t.Fatal(err)
	}

	// Build the producer-conformant signed batch with one safety frame.
	payload := []byte(`{"safety_event":{"kind":"MAN_OVERBOARD","summary":"MOB starboard side","latitude":3.8,"longitude":9.7,"persons_at_risk":1}}`)
	payloadDigest := sha256.Sum256(payload)
	frame := BatchFrame{
		DeviceID: "dev-kafka-1", GatewayID: "gw-1", SourceSequence: 42,
		ObservedAt: "2026-08-29T12:00:00Z", ReceivedAt: "2026-08-29T12:00:01Z",
		DataClassification: "RESTRICTED", PayloadBase64: base64.StdEncoding.EncodeToString(payload),
		PayloadSHA256: hex.EncodeToString(payloadDigest[:]),
	}
	batchKey := batchKeyDigest(waterwayTopic, []BatchFrame{frame})
	frameJSON, _ := json.Marshal(frame)
	var frameValue any
	if err := json.Unmarshal(frameJSON, &frameValue); err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"batchKey": batchKey, "encoding": "json-lines", "frameCount": float64(1),
		"frames": []any{frameValue}, "producer": "waterway-safety", "schema": WaterwayBatchSchemaDomain,
		"topic": waterwayTopic,
	}
	fleetSigner, err := provenance.NewSigner("waterway-safety-1", fleetPriv)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := provenance.Canonicalize(document)
	if err != nil {
		t.Fatal(err)
	}
	batchSig, err := fleetSigner.Sign(canonical)
	if err != nil {
		t.Fatal(err)
	}
	headerJSON, _ := json.Marshal(map[string]any{
		"record_type": WaterwayBatchProvenanceRecordType, "batch_key": batchKey, "frame_count": 1,
		"producer": "waterway-safety", "schema": WaterwayBatchSchemaDomain, "topic": waterwayTopic,
		"signature_key_id": "waterway-safety-1", "signature": batchSig,
	})
	batchValue := append(append(headerJSON, '\n'), append(frameJSON, '\n')...)

	// Produce to the broker, consume with a fresh group, process.
	writer := &kafka.Writer{Addr: kafka.TCP(brokers...), RequiredAcks: kafka.RequireAll}
	if err := writer.WriteMessages(ctx, kafka.Message{
		Topic: waterwayTopic, Key: []byte(batchKey), Value: batchValue, Time: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: brokers, Topic: waterwayTopic, GroupID: fmt.Sprintf("sar-intake-it-%d", time.Now().UnixNano()),
		MinBytes: 1, MaxBytes: 4 << 20, StartOffset: kafka.FirstOffset,
	})
	defer reader.Close()
	fetchCtx, cancelFetch := context.WithTimeout(ctx, 30*time.Second)
	defer cancelFetch()
	message, err := reader.FetchMessage(fetchCtx)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := processor.ProcessWaterwayRecord(ctx, message.Key, message.Value)
	if err != nil {
		t.Fatal(err)
	}
	if admitted != 1 {
		t.Fatalf("expected 1 admitted safety event, got %d", admitted)
	}
	if err := reader.CommitMessages(ctx, message); err != nil {
		t.Fatal(err)
	}

	// A SAR case anchored to the feed-admitted incident exists.
	var caseID string
	if err := pool.QueryRow(ctx, `
		SELECT case_id FROM sar_cases c JOIN maritime_incidents i ON i.incident_id=c.incident_id
		WHERE i.source_event_id LIKE 'sar-intake-1:ww-%'`).Scan(&caseID); err != nil {
		t.Fatalf("sar case not created: %v", err)
	}

	// The emitted maritime.sar.v1 case_opened envelope round-trips through
	// the broker with signature verification (contracts convention).
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT payload FROM maritime_isr_outbox WHERE topic='maritime.sar.v1' AND event_type='maritime.sar.case_opened.v1' LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	emissionWriter := &kafka.Writer{Addr: kafka.TCP(brokers...), RequiredAcks: kafka.RequireAll}
	if err := emissionWriter.WriteMessages(ctx, kafka.Message{Topic: sarTopic, Key: []byte(caseID), Value: raw, Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	_ = emissionWriter.Close()
	sarReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: brokers, Topic: sarTopic, GroupID: fmt.Sprintf("sar-emit-it-%d", time.Now().UnixNano()),
		MinBytes: 1, MaxBytes: 4 << 20, StartOffset: kafka.FirstOffset,
	})
	defer sarReader.Close()
	emitted, err := sarReader.FetchMessage(fetchCtx)
	if err != nil {
		t.Fatal(err)
	}
	emissionDirectory, err := provenance.ParseDirectory([]byte(`{"sar-intake-1":"` + base64.RawURLEncoding.EncodeToString(intakePub) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := envelope.Admit(emitted.Value, emissionDirectory)
	if err != nil {
		t.Fatalf("brokered sar envelope fails signature verification: %v", err)
	}
	if parsed.EventType != envelope.EventSARCaseOpened {
		t.Fatalf("unexpected event type %q", parsed.EventType)
	}
}
