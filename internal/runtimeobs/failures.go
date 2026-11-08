package runtimeobs

import (
	"context"
	"errors"

	"github.com/dreadl0ck/netcap/internal/policy"
)

// NativeFailure deliberately discards diagnostic text and rule identifiers.
func NativeFailure(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, policy.ErrStateCapacity):
		return "state_capacity"
	case errors.Is(err, policy.ErrStateClock):
		return "state_clock"
	case errors.Is(err, policy.ErrWorkBudget):
		return "work_budget"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	default:
		return "evaluation_failed"
	}
}

func (m *Monitor) NativeError(err error) {
	if m != nil && err != nil {
		m.failures.WithLabelValues(NativeFailure(err)).Inc()
	}
}
