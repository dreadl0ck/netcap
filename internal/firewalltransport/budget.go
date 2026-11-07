package firewalltransport

import (
	"errors"
	"sync/atomic"
)

const DefaultMaxBufferedBytes int64 = 64 << 20
const MaxBufferBudgetBytes int64 = 1 << 30

var ErrBufferCapacity = errors.New("aggregate inspection buffer capacity exhausted")

// BufferBudget accounts retained body representations across HTTP spools,
// message gates and Coraza transactions sharing one runtime. Limits are immutable.
type BufferBudget struct {
	limit int64
	used  atomic.Int64
}

func NewBufferBudget(limit int64) (*BufferBudget, error) {
	if limit < 1 || limit > MaxBufferBudgetBytes {
		return nil, errors.New("buffer budget must be 1..1073741824 bytes")
	}
	return &BufferBudget{limit: limit}, nil
}
func (b *BufferBudget) Limit() int64 { return b.limit }
func (b *BufferBudget) Used() int64  { return b.used.Load() }
func (b *BufferBudget) Acquire(n int64) bool {
	if n < 0 {
		return false
	}
	for {
		old := b.used.Load()
		if n > b.limit-old {
			return false
		}
		if b.used.CompareAndSwap(old, old+n) {
			return true
		}
	}
}
func (b *BufferBudget) Release(n int64) {
	if n < 0 || b.used.Add(-n) < 0 {
		panic("inspection buffer budget underflow")
	}
}
