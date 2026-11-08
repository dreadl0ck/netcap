package rules

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

const maxPendingRecords = 4096
const maxPendingBytes = 32 << 20

type pendingRecord struct {
	scope  string
	record types.AuditRecord
	wire   []byte
	charge int
}

// OrderedStream owns one capture/source scope and a bounded reorder buffer.
// The caller advances capture-time watermarks only when earlier records can no
// longer arrive (or after its configured lateness allowance). Records at/below
// a committed watermark fail explicitly. Finish drains EOF in canonical order.
type OrderedStream struct {
	mu        sync.Mutex
	engine    *Engine
	scope     string
	pending   []pendingRecord
	bytes     int
	watermark int64
	finished  bool
	err       error
	lateness  int64
	maxSeen   int64
}

func NewOrderedStream(config *Config, writer AlertWriter, scope string) (*OrderedStream, error) {
	if scope == "" || len(scope) > 256 {
		return nil, errors.New("capture/source scope required")
	}
	if err := validateOrderedConfig(config); err != nil {
		return nil, err
	}
	e, err := NewEngineFromConfig(config, writer)
	if err != nil {
		return nil, err
	}
	return &OrderedStream{engine: e, scope: scope}, nil
}

func validateOrderedConfig(config *Config) error {
	if config != nil && config.CaptureTime != nil {
		return errors.New("explicit OrderedStream and capture_time config cannot be combined")
	}
	if config != nil {
		for _, rule := range config.Rules {
			if rule != nil && rule.Enabled && (rule.DistinctField != "" || rule.Threshold > 1 && len(rule.GroupBy) == 0 || rule.Sequence != nil && rule.Sequence.AfterType == "") {
				return errors.New("OrderedStream requires grouped counts and typed sequences; legacy distinct rules are unsupported")
			}
		}
	}
	return nil
}

func (s *OrderedStream) Push(record types.AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.push(record)
}

func (s *OrderedStream) push(record types.AuditRecord) error {
	return s.pushScoped(s.scope, record)
}

func (s *OrderedStream) pushScoped(scope string, record types.AuditRecord) error {
	if s.err != nil {
		return s.err
	}
	if s.finished {
		return errors.New("rule stream finalized")
	}
	if record == nil || reflect.ValueOf(record).Kind() == reflect.Pointer && reflect.ValueOf(record).IsNil() || record.Time() <= s.watermark {
		return errors.New("record timestamp is missing or at/below committed watermark")
	}
	message, ok := record.(proto.Message)
	if !ok {
		return errors.New("record must be a protobuf message")
	}
	if proto.Size(message) > 1<<20 || len(s.pending) >= maxPendingRecords {
		return ErrStateCapacity
	}
	wire, err := proto.Marshal(message)
	if err != nil {
		return err
	}
	charge := int(offlineMemory(reflect.ValueOf(record))) + len(wire) + len(scope) + 1024
	if s.bytes+charge > maxPendingBytes {
		return ErrStateCapacity
	}
	s.pending = append(s.pending, pendingRecord{scope: scope, record: proto.Clone(message).(types.AuditRecord), wire: wire, charge: charge})
	s.bytes += charge
	return nil
}

func (s *OrderedStream) observe(record types.AuditRecord) (int, error) {
	return s.observeScoped(s.scope, record)
}

func (s *OrderedStream) observeScoped(scope string, record types.AuditRecord) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.pushScoped(scope, record); err != nil {
		s.err = err
		return 0, err
	}
	if record.Time() > s.maxSeen {
		s.maxSeen = record.Time()
	}
	// Hold the boundary timestamp too, so equal-time records sort together.
	watermark := s.maxSeen - s.lateness - 1
	if watermark < s.watermark {
		watermark = s.watermark
	}
	return s.advance(watermark)
}

// Advance evaluates all admitted records at/below watermark. A write/evaluation
// error makes this stream terminal; retained evidence must be replayed in a new
// run rather than silently losing a threshold crossing on retry.
func (s *OrderedStream) Advance(watermark int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.advance(watermark)
}

func (s *OrderedStream) advance(watermark int64) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.finished {
		return 0, errors.New("rule stream finalized")
	}
	if watermark < s.watermark {
		return 0, errors.New("watermarks must be monotonic")
	}
	sort.SliceStable(s.pending, func(i, j int) bool {
		a, b := s.pending[i], s.pending[j]
		if a.record.Time() != b.record.Time() {
			return a.record.Time() < b.record.Time()
		}
		if a.record.NetcapType() != b.record.NetcapType() {
			return a.record.NetcapType() < b.record.NetcapType()
		}
		return bytes.Compare(a.wire, b.wire) < 0
	})
	count, consumed := 0, 0
	for _, p := range s.pending {
		if p.record.Time() > watermark {
			break
		}
		n, err := s.engine.EvaluateScoped(p.scope, p.record)
		count += n
		if err != nil {
			s.err = fmt.Errorf("ordered rule stream incomplete: %w", err)
			return count, s.err
		}
		consumed++
		s.bytes -= p.charge
	}
	copy(s.pending, s.pending[consumed:])
	clear(s.pending[len(s.pending)-consumed:])
	s.pending = s.pending[:len(s.pending)-consumed]
	s.watermark = watermark
	return count, nil
}

func (s *OrderedStream) Finish() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		return 0, s.err
	}
	count, err := s.advance(1<<63 - 1)
	if err == nil {
		s.finished = true
	}
	return count, err
}

// Reload refuses queued old-generation records. Flush an explicit watermark
// first; compilation failure preserves both active rules and correlation state.
func (s *OrderedStream) Reload(config *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.finished {
		return errors.New("rule stream finalized")
	}
	if len(s.pending) > 0 {
		return errors.New("advance pending records before reloading rules")
	}
	if err := validateOrderedConfig(config); err != nil {
		return err
	}
	return s.engine.UpdateConfig(config)
}

func (s *OrderedStream) Close() error {
	_, err := s.Finish()
	return errors.Join(err, s.engine.Close())
}
