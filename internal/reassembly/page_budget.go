package reassembly

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"
)

var ErrPageBudget = errors.New("TCP reassembly page budget exceeded")

// PageAllocationBytes conservatively credits both allocations, including Go
// size-class rounding. Small packets can use less than the maximum payload.
// Packet contexts, connection state, parser copies and RSS are outside this budget.
const PageAllocationBytes = 2048 + 2*int64(unsafe.Sizeof(page{}))

type PageBudget struct {
	limit                int64
	used, peak, rejected atomic.Int64
	exceeded             atomic.Bool
	once                 sync.Once
	cancel               func()
}

type PageBudgetHealth struct {
	Scope         string `json:"scope"`
	Policy        string `json:"policy"`
	LimitBytes    int64  `json:"limitBytes"`
	RetainedBytes int64  `json:"retainedBytes"`
	PeakBytes     int64  `json:"peakBytes"`
	RejectedBytes int64  `json:"rejectedBytes"`
	Exceeded      bool   `json:"exceeded"`
}

func NewPageBudget(limit int64, cancel func()) (*PageBudget, error) {
	if limit < 0 {
		return nil, fmt.Errorf("max-retained-reassembly-bytes cannot be negative")
	}
	if limit == 0 {
		return nil, nil
	}
	return &PageBudget{limit: limit, cancel: cancel}, nil
}

func (b *PageBudget) reserve(pages int) bool {
	if b == nil {
		return true
	}
	n := int64(pages) * PageAllocationBytes
	for {
		used := b.used.Load()
		if b.exceeded.Load() || n > b.limit-used {
			b.rejected.Add(n)
			b.once.Do(func() {
				b.exceeded.Store(true)
				if b.cancel != nil {
					b.cancel()
				}
			})
			return false
		}
		if b.used.CompareAndSwap(used, used+n) {
			for peak := b.peak.Load(); peak < used+n; peak = b.peak.Load() {
				if b.peak.CompareAndSwap(peak, used+n) {
					break
				}
			}
			return true
		}
	}
}

func (b *PageBudget) release() {
	if b.used.Add(-PageAllocationBytes) < 0 {
		panic("TCP reassembly page accounting underflow")
	}
}

func (b *PageBudget) Error() error {
	if b != nil && b.exceeded.Load() {
		return fmt.Errorf("%w: limit=%d bytes", ErrPageBudget, b.limit)
	}
	return nil
}

func (b *PageBudget) Health() PageBudgetHealth {
	return PageBudgetHealth{Scope: "tcp-reassembly-page-allocations", Policy: "abort-capture; no free-page cache", LimitBytes: b.limit,
		RetainedBytes: b.used.Load(), PeakBytes: b.peak.Load(), RejectedBytes: b.rejected.Load(), Exceeded: b.exceeded.Load()}
}

// Called only before assembly begins. Every worker of a capture shares b.
func (a *Assembler) SetPageBudget(b *PageBudget) {
	if a.pc.used != 0 || a.pc.size != 0 {
		panic("cannot replace an active assembler page budget")
	}
	a.pc.budget = b
}

func pageDiscard(half *halfconnection, n int, ac AssemblerContext) {
	if observer, ok := half.stream.(interface {
		ReassemblyDiscarded(TCPFlowDirection, int, AssemblerContext)
	}); ok {
		observer.ReassemblyDiscarded(half.dir, n, ac)
	}
}
