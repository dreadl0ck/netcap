package rules

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"reflect"
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
	mu           sync.Mutex
	engine       *Engine
	scope        string
	pending      []pendingRecord
	heaped       bool
	bytes        int
	watermark    int64
	hasWatermark bool
	finished     bool
	err          error
	lateness     int64
	maxSeen      int64
	hasSeen      bool
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
	if isNilAuditRecord(record) || record.Time() == 0 || s.hasWatermark && record.Time() <= s.watermark {
		return errors.New("record timestamp is missing or at/below committed watermark")
	}
	message, ok := record.(proto.Message)
	if !ok {
		return errors.New("record must be a protobuf message")
	}
	if len(s.pending) >= maxPendingRecords {
		return ErrStateCapacity
	}
	size := proto.Size(message)
	if size > 1<<20 {
		return ErrStateCapacity
	}
	retained := offlineMemory(reflect.ValueOf(record)) + int64(len(scope)) + 1024
	available := int64(maxPendingBytes - s.bytes)
	if retained+int64(size) > available {
		return ErrStateCapacity
	}
	wire, err := canonicalRuleRecord(message)
	if err != nil {
		return err
	}
	charge := retained + int64(len(wire))
	if len(wire) > 1<<20 || charge > available {
		return ErrStateCapacity
	}
	pending := pendingRecord{scope: scope, record: proto.Clone(message).(types.AuditRecord), wire: wire, charge: int(charge)}
	n := len(s.pending)
	if n > 0 && !s.heaped {
		// A sorted prefix already satisfies the min-heap invariant.
		s.heaped = pendingBefore(pending, s.pending[n-1])
	}
	s.pending = append(s.pending, pending)
	if s.heaped {
		i := n
		for i > 0 {
			parent := (i - 1) / 2
			if !pendingBefore(pending, s.pending[parent]) {
				break
			}
			s.pending[i] = s.pending[parent]
			i = parent
		}
		s.pending[i] = pending
	}
	s.bytes += pending.charge
	return nil
}

func canonicalRuleRecord(message proto.Message) ([]byte, error) {
	wire, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}
	if err := orderRuleRecordMaps(message, wire); err != nil {
		return nil, err
	}
	return wire, nil
}

func (s *OrderedStream) observe(record types.AuditRecord) (int, error) {
	return s.observeScoped(s.scope, record)
}

func (s *OrderedStream) observeScoped(scope string, record types.AuditRecord) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.pushScoped(scope, record); err != nil {
		s.fail(err)
		return 0, err
	}
	if !s.hasSeen || record.Time() > s.maxSeen {
		s.maxSeen, s.hasSeen = record.Time(), true
	}
	// Hold the boundary timestamp too, so equal-time records sort together.
	if s.maxSeen <= math.MinInt64+s.lateness {
		return 0, nil
	}
	watermark := s.maxSeen - s.lateness - 1
	if s.hasWatermark && watermark < s.watermark {
		watermark = s.watermark
	}
	return s.advance(watermark)
}

func (s *OrderedStream) fail(err error) {
	s.err = err
	s.pending = nil
	s.heaped = false
	s.bytes = 0
}

// Advance evaluates all admitted records at/below watermark. A write/evaluation
// error makes this stream terminal; retained evidence must be replayed in a new
// run rather than silently losing a threshold crossing on retry.
func (s *OrderedStream) Advance(watermark int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.advance(watermark)
}

func pendingBefore(a, b pendingRecord) bool {
	if a.record.Time() != b.record.Time() {
		return a.record.Time() < b.record.Time()
	}
	if a.record.NetcapType() != b.record.NetcapType() {
		return a.record.NetcapType() < b.record.NetcapType()
	}
	if order := bytes.Compare(a.wire, b.wire); order != 0 {
		return order < 0
	}
	return a.scope < b.scope
}

func (s *OrderedStream) removeHeapHead() {
	last := len(s.pending) - 1
	tail := s.pending[last]
	s.pending[last] = pendingRecord{}
	s.pending = s.pending[:last]
	if last == 0 {
		s.heaped = false
		return
	}
	i := 0
	for child := 1; child < last; child = 2*i + 1 {
		if right := child + 1; right < last && pendingBefore(s.pending[right], s.pending[child]) {
			child = right
		}
		if !pendingBefore(s.pending[child], tail) {
			break
		}
		s.pending[i] = s.pending[child]
		i = child
	}
	s.pending[i] = tail
}

func (s *OrderedStream) advance(watermark int64) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.finished {
		return 0, errors.New("rule stream finalized")
	}
	if s.hasWatermark && watermark < s.watermark {
		return 0, errors.New("watermarks must be monotonic")
	}
	if len(s.pending) == 0 || watermark < s.pending[0].record.Time() {
		s.watermark, s.hasWatermark = watermark, true
		return 0, nil
	}
	count, consumed := 0, 0
	for consumed < len(s.pending) {
		p := s.pending[consumed]
		if p.record.Time() > watermark {
			break
		}
		n, err := s.engine.EvaluateScoped(p.scope, p.record)
		count += n
		if err != nil {
			s.fail(fmt.Errorf("ordered rule stream incomplete: %w", err))
			return count, s.err
		}
		if s.heaped {
			s.removeHeapHead()
		} else {
			consumed++
		}
		s.bytes -= p.charge
	}
	clear(s.pending[:consumed])
	if consumed == len(s.pending) {
		s.pending = s.pending[:0]
	} else {
		s.pending = s.pending[consumed:]
	}
	s.watermark, s.hasWatermark = watermark, true
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
