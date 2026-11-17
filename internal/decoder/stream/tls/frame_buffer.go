package tls

import (
	"fmt"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

func appendFrameBuffer(data []byte, credit int64, budget *core.StateBudget, more []byte, limit int) ([]byte, int64, error) {
	if len(more) > limit-len(data) {
		return data, credit, fmt.Errorf("TLS framing buffer exceeds limit")
	}
	if len(data)+len(more) > cap(data) {
		capacity := max(len(data)+len(more), min(limit, max(256, 2*cap(data))))
		amount := 2 * int64(capacity)
		if err := budget.Reserve(amount); err != nil {
			return data, credit, err
		}
		copyData := make([]byte, len(data), capacity)
		copy(copyData, data)
		budget.Release(credit)
		data, credit = copyData, amount
	}
	return append(data, more...), credit, nil
}
