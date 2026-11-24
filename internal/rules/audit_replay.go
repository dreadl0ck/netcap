package rules

import (
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// AuditReplay evaluates records in file order with a monotonic capture clock.
// Call Finalize at EOF to emit pending file findings.
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
	engine.projectReplayEvidence = true
	engine.replayFiles = &replayFileEvidence{writer: writer, window: engine.dedupWindow}
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
	n, err := r.engine.replayFiles.flush(r.watermark, false)
	if err != nil {
		return n, err
	}
	written, err := r.engine.Evaluate(record)
	return n + written, err
}

func (r *AuditReplay) Finalize() (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, err := r.engine.Finalize()
	if err != nil {
		return n, err
	}
	written, err := r.engine.replayFiles.flush(r.watermark, true)
	return n + written, err
}
