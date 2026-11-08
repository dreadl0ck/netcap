package tcp

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

// ErrRetainedPayloadLimit means reader-owned TCP payload could not be retained.
var ErrRetainedPayloadLimit = errors.New("TCP retained payload budget exceeded")

type payloadLimitFailure struct{ used, requested int64 }

type retainedPayloadBudget struct {
	limit                int64
	used, peak, rejected atomic.Int64
	failure              atomic.Pointer[payloadLimitFailure]
	failOnce             sync.Once
	onExceeded           func()
}

// PayloadRetentionHealth accounts for reader-owned TCP copies, not total process memory.
type PayloadRetentionHealth struct {
	Scope         string `json:"scope"`
	Policy        string `json:"policy"`
	LimitBytes    int64  `json:"limitBytes"`
	RetainedBytes int64  `json:"retainedBytes"`
	PeakBytes     int64  `json:"peakBytes"`
	RejectedBytes int64  `json:"rejectedBytes"`
	Exceeded      bool   `json:"exceeded"`
}

const maxPostCloseBytes = 64 << 10

func (t *tcpConnection) ObservePostClose() bool { return true }

func (t *tcpConnection) recordPostCloseDiscard(dir reassembly.TCPFlowDirection, size int, ac reassembly.AssemblerContext) {
	t.recordDiscard(&t.postCloseMarkers, "tcp-post-close-budget", dir, size, ac)
}

func (t *tcpConnection) recordRetentionDiscard(dir reassembly.TCPFlowDirection, size int, ac reassembly.AssemblerContext) {
	t.recordDiscard(&t.retentionMarkers, "tcp-retained-payload-budget", dir, size, ac)
}

func (t *tcpConnection) recordDiscard(markers *[2]*core.StreamData, reason string, dir reassembly.TCPFlowDirection, size int, ac reassembly.AssemblerContext) {
	if size <= 0 {
		return
	}
	index := 0
	reader := t.client
	if dir == reassembly.TCPDirServerToClient {
		index, reader = 1, t.server
	}
	t.Lock()
	marker := markers[index]
	created := marker == nil
	if created {
		marker = &core.StreamData{Dir: dir, AssemblerContext: ac, CaptureInformation: ac.GetCaptureInfo(), DiscardReason: reason}
		markers[index] = marker
	}
	marker.DiscardedBytes += int64(size)
	t.Unlock()
	if created {
		reader.StoreData(marker)
	}
}

func (b *retainedPayloadBudget) reserve(size int64) bool {
	if b.failure.Load() != nil {
		b.rejected.Add(size)
		return false
	}
	for {
		used := b.used.Load()
		if size > b.limit-used {
			b.rejected.Add(size)
			b.failOnce.Do(func() {
				b.failure.Store(&payloadLimitFailure{used: used, requested: size})
				if b.onExceeded != nil {
					b.onExceeded()
				}
			})
			return false
		}
		if b.used.CompareAndSwap(used, used+size) {
			for peak := b.peak.Load(); peak < used+size; peak = b.peak.Load() {
				if b.peak.CompareAndSwap(peak, used+size) {
					break
				}
			}
			return true
		}
	}
}

func (b *retainedPayloadBudget) release(size int64) {
	if b.used.Add(-size) < 0 {
		panic("TCP retained payload accounting underflow")
	}
}

func (f *connectionFactory) configurePayloadBudget(limit int64, cancel func()) error {
	if limit < 0 {
		return fmt.Errorf("max-retained-tcp-bytes cannot be negative")
	}
	f.Lock()
	defer f.Unlock()
	for _, reader := range f.streamReaders {
		if reader != nil {
			return fmt.Errorf("cannot replace TCP payload budget while readers are registered")
		}
	}
	f.payloadBudget = nil
	if limit > 0 {
		f.payloadBudget = &retainedPayloadBudget{limit: limit, onExceeded: cancel}
	}
	return nil
}

// ConfigureRetainedPayloadBudget must run before this capture creates stream readers.
func ConfigureRetainedPayloadBudget(limit int64, cancel func()) error {
	return StreamFactory.configurePayloadBudget(limit, cancel)
}

// PayloadRetentionError preserves an abort cause until capture finalization resets the factory.
func PayloadRetentionError() error {
	StreamFactory.Lock()
	budget := StreamFactory.payloadBudget
	StreamFactory.Unlock()
	if budget != nil {
		if failure := budget.failure.Load(); failure != nil {
			return fmt.Errorf("%w: limit=%d retained=%d requested=%d bytes", ErrRetainedPayloadLimit, budget.limit, failure.used, failure.requested)
		}
	}
	return nil
}

func payloadRetentionSnapshot() *PayloadRetentionHealth {
	StreamFactory.Lock()
	budget := StreamFactory.payloadBudget
	StreamFactory.Unlock()
	if budget == nil {
		return nil
	}
	return &PayloadRetentionHealth{Scope: "tcp-reader-payload", Policy: "abort-capture", LimitBytes: budget.limit,
		RetainedBytes: budget.used.Load(), PeakBytes: budget.peak.Load(), RejectedBytes: budget.rejected.Load(), Exceeded: budget.failure.Load() != nil}
}
