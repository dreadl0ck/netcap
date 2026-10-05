package dpi

import "time"

// RuntimeConfig controls the throughput/native-context-memory tradeoff and flow retention.
// Zero values select automatic workers (up to 8), 65,536 flows, and a five-minute idle timeout.
type RuntimeConfig struct {
	Workers     int
	MaxFlows    int
	IdleTimeout time.Duration
}
