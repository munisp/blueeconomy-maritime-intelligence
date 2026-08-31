// isr-worker runs the Temporal worker hosting ISRResponseWorkflow, the Deep
// Blue Project ISR response rail (alert -> classification -> dispatch ->
// interdiction -> outcome capture). It is environment-configured and fails
// closed when Temporal or PostgreSQL is unavailable.
//
// Activity side effects are durable envelopes appended to the transactional
// ISR outbox (maritime_isr_outbox), drained to Kafka by the
// maritime-intelligence-outbox-publisher. The activity signatures fixed by
// the workflow package do not carry the alert's classification label, so
// audit/outcome envelopes are labelled RESTRICTED — the minimum operational
// label; observers holding the alert's clearance replay full detail through
// the workflow state/history queries.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	sdkworkflow "go.temporal.io/sdk/workflow"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	isrworkflow "github.com/munisp/blueeconomy-maritime-intelligence/internal/workflow"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("isr-worker failed", "error", err.Error())
		os.Exit(1)
	}
}

func required(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

// transitionAuditEvent is the maritime.isr.v1 payload for one recorded
// lifecycle transition.
type transitionAuditEvent struct {
	AlertID        string `json:"alert_id"`
	From           string `json:"from"`
	To             string `json:"to"`
	Actor          string `json:"actor"`
	Detail         string `json:"detail"`
	Classification string `json:"classification"`
}

// outcomeRecordedEvent is the maritime.outcome.v1 payload for the terminal
// outcome capture.
type outcomeRecordedEvent struct {
	AlertID        string `json:"alert_id"`
	IncidentRef    string `json:"incident_ref"`
	Verified       bool   `json:"verified"`
	Classification string `json:"classification"`
}

// outboxActivities persists workflow side effects into maritime_isr_outbox so
// delivery to Kafka rides the existing transactional outbox publisher.
type outboxActivities struct{ pool *pgxpool.Pool }

func (activities *outboxActivities) appendOutbox(ctx context.Context, topic, eventType, aggregateKey string, payload any) error {
	occurredAt := time.Now().UTC()
	envelope, encoded, err := isr.Seal(topic, eventType, aggregateKey, isr.ClassificationRestricted, occurredAt, payload)
	if err != nil {
		return err
	}
	// The outbox payload column carries the canonical encoded envelope; the
	// publisher delivers it verbatim to Kafka. The classification column keeps
	// the record-level clearance label (DB CHECK).
	if _, err := activities.pool.Exec(ctx, `
		INSERT INTO maritime_isr_outbox (event_id, topic, event_type, classification, aggregate_key, payload, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.New(), envelope.Topic, envelope.EventType, string(envelope.Clearance), envelope.AggregateKey, encoded, occurredAt); err != nil {
		return fmt.Errorf("write %s outbox event: %w", eventType, err)
	}
	return nil
}

func (activities *outboxActivities) auditTransition(ctx context.Context, alertID string, entry isrworkflow.AuditEntry) error {
	return activities.appendOutbox(ctx, isr.TopicISR, "isr.response_transition", alertID, transitionAuditEvent{
		AlertID:        alertID,
		From:           string(entry.From),
		To:             string(entry.To),
		Actor:          entry.Actor,
		Detail:         entry.Detail,
		Classification: string(isr.ClassificationRestricted),
	})
}

func (activities *outboxActivities) recordOutcome(ctx context.Context, alertID, incidentRef string, verified bool) error {
	return activities.appendOutbox(ctx, isr.TopicOutcome, "isr.outcome_recorded", alertID, outcomeRecordedEvent{
		AlertID:        alertID,
		IncidentRef:    incidentRef,
		Verified:       verified,
		Classification: string(isr.ClassificationRestricted),
	})
}

func run(logger *slog.Logger) error {
	databaseURL, err := required("DATABASE_URL")
	if err != nil {
		return err
	}
	temporalAddress, err := required("TEMPORAL_ADDRESS")
	if err != nil {
		return err
	}
	temporalNamespace, err := required("TEMPORAL_NAMESPACE")
	if err != nil {
		return err
	}
	taskQueue, err := required("TEMPORAL_TASK_QUEUE")
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}

	temporalClient, err := client.Dial(client.Options{
		HostPort:  temporalAddress,
		Namespace: temporalNamespace,
		Logger:    logger,
	})
	if err != nil {
		return fmt.Errorf("dial temporal: %w", err)
	}
	defer temporalClient.Close()

	durable := &outboxActivities{pool: pool}
	activities := &isrworkflow.Activities{
		AuditTransition: durable.auditTransition,
		RecordOutcome:   durable.recordOutcome,
	}
	definition, err := isrworkflow.NewISRWorkflow(activities)
	if err != nil {
		return err
	}

	temporalWorker := worker.New(temporalClient, taskQueue, worker.Options{})
	temporalWorker.RegisterWorkflowWithOptions(definition.ISRResponseWorkflow, sdkworkflow.RegisterOptions{Name: "ISRResponseWorkflow"})
	temporalWorker.RegisterActivityWithOptions(activities.AuditTransition, activity.RegisterOptions{Name: isrworkflow.ActivityAuditTransition})
	temporalWorker.RegisterActivityWithOptions(activities.RecordOutcome, activity.RegisterOptions{Name: isrworkflow.ActivityRecordOutcome})

	// Optional health probe for orchestrators: enabled only when
	// ISR_WORKER_HEALTH_ADDR is set (e.g. ":8081").
	var healthServer *http.Server
	if addr := strings.TrimSpace(os.Getenv("ISR_WORKER_HEALTH_ADDR")); addr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		healthServer = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("isr-worker health listener failed", "error", err.Error())
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = healthServer.Shutdown(shutdownCtx)
		}()
	}

	logger.Info("isr-worker starting", "task_queue", taskQueue, "namespace", temporalNamespace)
	errCh := make(chan error, 1)
	go func() { errCh <- temporalWorker.Run(worker.InterruptCh()) }()
	select {
	case <-ctx.Done():
		temporalWorker.Stop()
		return nil
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("run temporal worker: %w", err)
		}
		return nil
	}
}
