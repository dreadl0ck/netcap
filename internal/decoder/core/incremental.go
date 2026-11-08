package core

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// IncrementalFactory is opt-in. Push owns no input after returning: retained
// bytes/metadata must be copied under StateBudget. Finish emits the final tail
// once; Abort releases ownership without interpreting omitted bytes as EOF.
type IncrementalFactory interface {
	NewIncremental(*ConversationInfo, *StateBudget) IncrementalDecoder
}

type IncrementalDecoder interface {
	Push(*StreamData) error
	Finish(StreamCompletion) error
	Abort()
}

type StreamCompletion struct {
	Reason    string
	ClientFIN bool
	ServerFIN bool
}

type IncrementalReport struct {
	Protocol              string `json:"protocol"`
	CompletedTransactions uint64 `json:"completedTransactions"`
	GapResets             uint64 `json:"gapResets"`
	DeferredTail          string `json:"deferredTail,omitempty"`
}

type IncrementalReporter interface{ IncrementalReport() IncrementalReport }

// The tail is borrowed only during the callback, while its parser reservations
// remain held. Existing upgrade decoders can inspect deferred bytes here.
type IncrementalTailObserver interface{ SetTailObserver(func(*ConversationInfo)) }

var ErrStreamStateBudget = errors.New("TCP stream state budget exceeded")

var ErrIncrementalLimit = errors.New("incremental parser retained-state limit")

type StateBudget struct {
	limit                int64
	used, peak, rejected atomic.Int64
	failed               atomic.Bool
	once                 sync.Once
	cancel               func()
}

type StateBudgetHealth struct {
	Scope         string `json:"scope"`
	LimitBytes    int64  `json:"limitBytes"`
	RetainedBytes int64  `json:"retainedBytes"`
	PeakBytes     int64  `json:"peakBytes"`
	RejectedBytes int64  `json:"rejectedBytes"`
	Exceeded      bool   `json:"exceeded"`
}

func NewStateBudget(limit int64, cancel func()) (*StateBudget, error) {
	if limit < 0 {
		return nil, fmt.Errorf("max-retained-tcp-state-bytes cannot be negative")
	}
	return &StateBudget{limit: limit, cancel: cancel}, nil
}

func (b *StateBudget) Reserve(n int64) error {
	if n < 0 {
		panic("negative stream reservation")
	}
	if b == nil {
		return nil
	}
	for {
		used := b.used.Load()
		if b.failed.Load() || (b.limit > 0 && n > b.limit-used) {
			b.rejected.Add(n)
			b.once.Do(func() {
				b.failed.Store(true)
				if b.cancel != nil {
					b.cancel()
				}
			})
			return ErrStreamStateBudget
		}
		if b.used.CompareAndSwap(used, used+n) {
			for peak := b.peak.Load(); peak < used+n; peak = b.peak.Load() {
				if b.peak.CompareAndSwap(peak, used+n) {
					break
				}
			}
			return nil
		}
	}
}

func (b *StateBudget) Release(n int64) {
	if b != nil && b.used.Add(-n) < 0 {
		panic("stream state accounting underflow")
	}
}

func (b *StateBudget) Error() error {
	if b != nil && b.failed.Load() {
		return fmt.Errorf("%w: limit=%d", ErrStreamStateBudget, b.limit)
	}
	return nil
}

func (b *StateBudget) Health() StateBudgetHealth {
	return StateBudgetHealth{Scope: "tcp-pool-slot-and-connection-credits-and-incremental-parser-storage", LimitBytes: b.limit, RetainedBytes: b.used.Load(), PeakBytes: b.peak.Load(), RejectedBytes: b.rejected.Load(), Exceeded: b.failed.Load()}
}
