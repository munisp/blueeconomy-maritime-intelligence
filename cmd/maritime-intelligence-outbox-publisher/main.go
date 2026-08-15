package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
	"github.com/segmentio/kafka-go"
)

type config struct {
	databaseURL   string
	brokers       []string
	topic         string
	workerID      string
	lease         time.Duration
	pollInterval  time.Duration
	maxBackoff    time.Duration
	migrationPath string
	transport     string
}

func main() {
	if err := run(); err != nil {
		log.Printf("maritime-intelligence-outbox-publisher: %v", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	store, err := incident.Open(ctx, cfg.databaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	for _, path := range strings.Split(cfg.migrationPath, ",") {
		migration, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read migration %q: %w", path, readErr)
		}
		if execErr := store.Exec(ctx, string(migration)); execErr != nil {
			return fmt.Errorf("apply migration %q: %w", path, execErr)
		}
	}
	writer := &kafka.Writer{
		Addr:         kafka.TCP(cfg.brokers...),
		Topic:        cfg.topic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireAll,
		Async:        false,
	}
	defer writer.Close()
	publisher := &worker{store: store, writer: writer, cfg: cfg}
	log.Printf("outbox publisher %s delivering to Kafka topic %s via %s", cfg.workerID, cfg.topic, strings.Join(cfg.brokers, ","))
	return publisher.loop(ctx)
}

type worker struct {
	store  *incident.Store
	writer *kafka.Writer
	cfg    config
}

func (w *worker) loop(ctx context.Context) error {
	ticker := time.NewTicker(w.cfg.pollInterval)
	defer ticker.Stop()
	for {
		if err := w.deliverOne(ctx); err != nil && !errors.Is(err, incident.ErrNoPendingOutbox) {
			log.Printf("outbox delivery: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (w *worker) deliverOne(ctx context.Context) error {
	event, err := w.store.ClaimOutbox(ctx, w.cfg.workerID, w.cfg.lease)
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = w.writer.WriteMessages(writeCtx, kafka.Message{
		Key:   []byte(event.EventID.String()),
		Value: event.Payload,
		Headers: []kafka.Header{
			{Key: "x-blueeconomy-event-id", Value: []byte(event.EventID.String())},
			{Key: "x-blueeconomy-event-type", Value: []byte(event.EventType)},
		},
	})
	if err == nil {
		return w.store.MarkOutboxPublished(ctx, event.EventID, w.cfg.workerID)
	}
	retryAt := time.Now().UTC().Add(backoff(event.Attempts, w.cfg.maxBackoff))
	markErr := w.store.MarkOutboxFailed(ctx, event.EventID, w.cfg.workerID, err.Error(), retryAt)
	if markErr != nil {
		return fmt.Errorf("Kafka delivery failed: %v; release failed: %w", err, markErr)
	}
	return err
}

func backoff(attempts int, max time.Duration) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	if attempts > 30 {
		attempts = 30
	}
	delay := time.Second * time.Duration(1<<uint(attempts-1))
	if delay > max {
		return max
	}
	return delay
}

func loadConfig() (config, error) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return config{}, errors.New("DATABASE_URL must be set")
	}
	brokers := splitNonEmpty(os.Getenv("KAFKA_BROKERS"))
	if len(brokers) == 0 {
		return config{}, errors.New("KAFKA_BROKERS must contain at least one broker")
	}
	topic := os.Getenv("KAFKA_TOPIC")
	if strings.TrimSpace(topic) == "" || strings.TrimSpace(topic) != topic {
		return config{}, errors.New("KAFKA_TOPIC must be canonical non-empty text")
	}
	transport := os.Getenv("KAFKA_TRANSPORT")
	if transport == "" {
		transport = "local_plaintext"
	}
	if transport != "local_plaintext" && transport != "tls" {
		return config{}, errors.New("KAFKA_TRANSPORT must be local_plaintext or tls")
	}
	if transport == "tls" {
		return config{}, errors.New("KAFKA_TRANSPORT=tls requires Ministry-approved TLS/SASL configuration before enablement")
	}
	workerID := os.Getenv("OUTBOX_WORKER_ID")
	if strings.TrimSpace(workerID) == "" || strings.TrimSpace(workerID) != workerID {
		return config{}, errors.New("OUTBOX_WORKER_ID must be canonical non-empty text")
	}
	lease, err := durationEnv("OUTBOX_LEASE", 60*time.Second)
	if err != nil {
		return config{}, err
	}
	poll, err := durationEnv("OUTBOX_POLL_INTERVAL", 500*time.Millisecond)
	if err != nil {
		return config{}, err
	}
	maxBackoff, err := durationEnv("OUTBOX_MAX_BACKOFF", 5*time.Minute)
	if err != nil {
		return config{}, err
	}
	migrationPath := os.Getenv("MIGRATION_PATH")
	if migrationPath == "" {
		return config{}, errors.New("MIGRATION_PATH must be set")
	}
	return config{databaseURL: databaseURL, brokers: brokers, topic: topic, workerID: workerID,
		lease: lease, pollInterval: poll, maxBackoff: maxBackoff, migrationPath: migrationPath, transport: transport}, nil
}

func durationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration: %q", name, value)
	}
	return parsed, nil
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
