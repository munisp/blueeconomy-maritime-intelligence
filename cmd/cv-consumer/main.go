// cv-consumer admits signed blueeconomy-cv-service events
// (cv.vessel-detection.v1, cv.dark-vessel.v1) into the maritime-intelligence
// track-fusion engine and starts one ISRResponseWorkflow per dark-vessel
// anomaly — wiring the previously external starter rail in-service.
//
// Fail-closed configuration (all required):
//
//	KAFKA_BROKERS          comma-separated bootstrap brokers
//	KAFKA_GROUP_ID         consumer group (e.g. maritime-intelligence-cv)
//	KEY_DIRECTORY_PATH     producer public-key directory JSON (mandatory —
//	                       envelopes that fail JWS-EdDSA/JCS verification are
//	                       rejected and counted, never processed)
//	TEMPORAL_ADDRESS       Temporal frontend host:port
//	TEMPORAL_NAMESPACE     Temporal namespace
//	TEMPORAL_TASK_QUEUE    task queue hosting ISRResponseWorkflow
//
// Tracks are persisted through the in-memory fusion engine plus the anomaly
// recorder; deployments that need durable replay wire the store-backed
// recorder from cmd/maritime-intelligence.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/cvconsumer"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/tracks"
	isrworkflow "github.com/munisp/blueeconomy-maritime-intelligence/internal/workflow"
)

func required(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

// temporalStarter starts one ISRResponseWorkflow per anomaly with the
// anomaly ID as the workflow ID (idempotent: a duplicate start is a no-op
// success for an already-running instance).
type temporalStarter struct {
	temporal  client.Client
	taskQueue string
}

func (s *temporalStarter) StartISR(ctx context.Context, input isrworkflow.AlertInput) error {
	options := client.StartWorkflowOptions{
		ID:                                       input.AnomalyID,
		TaskQueue:                                s.taskQueue,
		WorkflowExecutionErrorWhenAlreadyStarted: true,
	}
	_, err := s.temporal.ExecuteWorkflow(ctx, options, "ISRResponseWorkflow", input)
	if err != nil {
		var alreadyStarted *serviceerror.WorkflowExecutionAlreadyStarted
		if errors.As(err, &alreadyStarted) {
			return nil // idempotent restart per anomaly
		}
		return err
	}
	return nil
}

// logAnomalyRecorder persists anomalies nowhere durable in this binary; it
// logs counts only (classified-data discipline) and relies on the workflow
// start as the actionable side effect. Deployments wire the store-backed
// recorder for the full outbox trail.
type logAnomalyRecorder struct{ logger *slog.Logger }

func (r *logAnomalyRecorder) RecordAnomalies(ctx context.Context, anomalies []tracks.Anomaly) error {
	r.logger.InfoContext(ctx, "cv anomalies admitted", "anomaly_count", len(anomalies))
	return nil
}

func run(ctx context.Context, logger *slog.Logger) error {
	brokersRaw, err := required("KAFKA_BROKERS")
	if err != nil {
		return err
	}
	groupID, err := required("KAFKA_GROUP_ID")
	if err != nil {
		return err
	}
	if _, err := required("TEMPORAL_ADDRESS"); err != nil {
		return err
	}
	namespace, err := required("TEMPORAL_NAMESPACE")
	if err != nil {
		return err
	}
	taskQueue, err := required("TEMPORAL_TASK_QUEUE")
	if err != nil {
		return err
	}

	// Mandatory producer key directory — fail closed.
	directory, err := provenance.LoadDirectoryFromEnv()
	if err != nil {
		return err
	}

	temporalClient, err := client.Dial(client.Options{
		HostPort:  os.Getenv("TEMPORAL_ADDRESS"),
		Namespace: namespace,
	})
	if err != nil {
		return fmt.Errorf("dial temporal: %w", err)
	}
	defer temporalClient.Close()

	config := tracks.DefaultConfig()
	if err := config.Validate(); err != nil {
		return err
	}
	engine, err := tracks.NewEngine(config, nil, nil, time.Now, func() string {
		return "cv-track-" + uuid.NewString()
	})
	if err != nil {
		return err
	}

	starter := &temporalStarter{temporal: temporalClient, taskQueue: taskQueue}
	consumer, err := cvconsumer.New(directory, engine, &logAnomalyRecorder{logger}, starter, nil, logger, func() string {
		return uuid.NewString()
	})
	if err != nil {
		return err
	}

	brokers := strings.Split(brokersRaw, ",")
	readers := []*kafka.Reader{
		kafka.NewReader(kafka.ReaderConfig{
			Brokers: brokers, GroupID: groupID, Topic: cvconsumer.TopicVesselDetection,
			MinBytes: 1, MaxBytes: 10 << 20,
		}),
		kafka.NewReader(kafka.ReaderConfig{
			Brokers: brokers, GroupID: groupID, Topic: cvconsumer.TopicDarkVessel,
			MinBytes: 1, MaxBytes: 10 << 20,
		}),
	}
	defer func() {
		for _, reader := range readers {
			_ = reader.Close()
		}
	}()

	logger.Info("cv-consumer started",
		"topics", []string{cvconsumer.TopicVesselDetection, cvconsumer.TopicDarkVessel},
		"group", groupID, "task_queue", taskQueue)

	errCh := make(chan error, len(readers))
	for _, reader := range readers {
		reader := reader
		go func() {
			for {
				message, err := reader.FetchMessage(ctx)
				if err != nil {
					if ctx.Err() != nil {
						errCh <- nil
						return
					}
					errCh <- fmt.Errorf("fetch %s: %w", reader.Config().Topic, err)
					return
				}
				var handleErr error
				switch reader.Config().Topic {
				case cvconsumer.TopicVesselDetection:
					handleErr = consumer.HandleVesselDetection(ctx, message.Value)
				case cvconsumer.TopicDarkVessel:
					handleErr = consumer.HandleDarkVessel(ctx, message.Value)
				}
				if handleErr != nil {
					// Rejected/failed records are logged with reason only;
					// the offset is NOT committed so the record is retried.
					logger.Error("cv record rejected", "topic", reader.Config().Topic,
						"offset", message.Offset, "error", handleErr.Error())
					continue
				}
				if err := reader.CommitMessages(ctx, message); err != nil && ctx.Err() == nil {
					logger.Error("offset commit failed", "topic", reader.Config().Topic, "error", err.Error())
				}
			}
		}()
	}

	for range readers {
		if err := <-errCh; err != nil {
			return err
		}
	}
	return nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger); err != nil && ctx.Err() == nil {
		logger.Error("cv-consumer failed", "error", err.Error())
		os.Exit(1)
	}
}
