package telemetry

import (
	"context"

	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel"
)

// headerCarrier adapts Kafka message headers to the OpenTelemetry text-map
// carrier so W3C traceparent/baggage ride inside outbox envelopes. Header
// keys are case-insensitive per the Kafka protocol convention used here.
type headerCarrier []kafka.Header

func (carrier headerCarrier) Get(key string) string {
	for _, header := range carrier {
		if header.Key == key {
			return string(header.Value)
		}
	}
	return ""
}

func (carrier *headerCarrier) Set(key, value string) {
	for index, header := range *carrier {
		if header.Key == key {
			(*carrier)[index].Value = []byte(value)
			return
		}
	}
	*carrier = append(*carrier, kafka.Header{Key: key, Value: []byte(value)})
}

func (carrier headerCarrier) Keys() []string {
	keys := make([]string, 0, len(carrier))
	for _, header := range carrier {
		keys = append(keys, header.Key)
	}
	return keys
}

// InjectKafkaHeaders writes the W3C traceparent/baggage of ctx into the
// message headers, replacing any stale values. Producers call this so
// consumers can continue the trace across the async boundary.
func InjectKafkaHeaders(ctx context.Context, headers []kafka.Header) []kafka.Header {
	carrier := headerCarrier(headers)
	otel.GetTextMapPropagator().Inject(ctx, &carrier)
	return carrier
}

// ExtractKafkaContext reads the W3C traceparent/baggage from consumed message
// headers. Messages without trace headers yield the caller's context
// unchanged, so uninstrumented producers never break consumers.
func ExtractKafkaContext(ctx context.Context, headers []kafka.Header) context.Context {
	carrier := headerCarrier(headers)
	return otel.GetTextMapPropagator().Extract(ctx, &carrier)
}
