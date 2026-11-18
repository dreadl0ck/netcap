package rules

import (
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// AuditReplay evaluates records in file order. Its clock starts at the first
// nonzero timestamp and never moves backward after that.
type AuditReplay struct {
	mu        sync.Mutex
	engine    *Engine
	watermark int64
	hasTime   bool
}

func NewAuditReplay(config *Config, writer AlertWriter) (*AuditReplay, error) {
	engine, err := NewEngineFromConfig(config, writer)
	if err != nil {
		return nil, err
	}
	replay := &AuditReplay{engine: engine}
	engine.clock = func() time.Time { return time.Unix(0, replay.watermark).UTC() }
	return replay, nil
}

func (r *AuditReplay) Evaluate(record types.AuditRecord) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !isNilAuditRecord(record) {
		if ts := record.Time(); ts != 0 && (!r.hasTime || ts > r.watermark) {
			r.watermark, r.hasTime = ts, true
		}
	}
	return r.engine.Evaluate(record)
}

func (r *AuditReplay) Finalize() (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.engine.Finalize()
}
