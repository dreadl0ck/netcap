package behavior

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

type Engine struct {
	mu       sync.Mutex
	config   Config
	state    Snapshot
	sink     AlertSink
	recent   map[string]int64
	err      error
	closed   bool
	lease    *os.File
	prefixes []Fact
}

func Open(config Config, sink AlertSink) (*Engine, error) {
	if config.Path == "" || sink == nil {
		return nil, errors.New("baseline path and alert sink are required")
	}
	if config.MinLearning == 0 {
		config.MinLearning = 7 * 24 * time.Hour
	}
	if config.MinSamples == 0 {
		config.MinSamples = 100
	}
	if config.MaxFacts == 0 {
		config.MaxFacts = 10000
	}
	if config.DedupWindow == 0 {
		config.DedupWindow = 5 * time.Minute
	}
	if config.MinLearning < 0 || config.MaxFacts < 1 || config.MaxFacts > 100000 || config.DedupWindow < 0 {
		return nil, errors.New("invalid baseline limits")
	}
	path, err := filepath.Abs(config.Path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	config.Path = filepath.Join(dir, filepath.Base(path))
	lease, err := os.OpenFile(config.Path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockBaseline(lease); err != nil {
		return nil, errors.Join(err, lease.Close())
	}
	success := false
	defer func() {
		if !success {
			_ = lease.Close()
		}
	}()
	e := &Engine{config: config, sink: sink, recent: make(map[string]int64), lease: lease}
	state, err := ReadSnapshot(config.Path)
	if err == nil {
		e.state = state
		if len(state.Observed) > config.MaxFacts || len(state.Approved) > config.MaxFacts {
			return nil, errors.New("baseline exceeds configured fact limit")
		}
		// A restarted baseline retains its learning criteria.
		e.config.MinLearning = time.Duration(state.MinLearningNS)
		e.config.MinSamples = state.MinSamples
		e.state.MaxFacts = config.MaxFacts
	} else if errors.Is(err, os.ErrNotExist) {
		e.state = Snapshot{Schema: SchemaVersion, Mode: Learning, MinLearningNS: int64(config.MinLearning), MinSamples: config.MinSamples,
			MaxFacts: config.MaxFacts, Observed: make(map[string]Observation), Approved: make(map[string]Fact), Suppressed: make(map[string]string)}
	} else {
		return nil, err
	}
	success = true
	return e, nil
}

// Observe uses capture time, including for replay. It does not approve new facts.
func (e *Engine) Observe(at time.Time, facts ...Fact) error {
	if at.IsZero() || at.UnixNano() <= 0 {
		return errors.New("observation requires a positive capture timestamp")
	}
	// Normalize copies before changing any state.
	normalized := make([]Fact, len(facts))
	for i, f := range facts {
		f.Scope.VLANs = append([]uint16(nil), f.Scope.VLANs...)
		if err := f.normalize(); err != nil {
			return err
		}
		normalized[i] = f
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return os.ErrClosed
	}
	if e.err != nil {
		return e.err
	}
	if e.state.Mode == Paused {
		return nil
	}
	ns := at.UnixNano()
	if ns < e.state.Watermark {
		e.state.OutOfOrder++
	}
	if ns > e.state.Watermark {
		e.state.Watermark = ns
	}
	if e.state.LearningStarted == 0 {
		e.state.LearningStarted = ns
	}
	if e.state.Mode == Learning && ns < e.state.LearningStarted {
		e.state.LearningStarted = ns
	}
	e.state.Samples++
	normalized = append(normalized, e.prefixes...)
	for _, fact := range normalized {
		id := factID(fact)
		observation, exists := e.state.Observed[id]
		if !exists {
			if len(e.state.Observed) >= e.config.MaxFacts {
				e.state.Overflow++
				continue
			}
			observation = Observation{Fact: fact, FirstSeen: ns, LastSeen: ns}
		}
		if ns < observation.FirstSeen {
			observation.FirstSeen = ns
		}
		if ns > observation.LastSeen {
			observation.LastSeen = ns
		}
		observation.Samples++
		e.state.Observed[id] = observation
		if e.state.Mode != Monitoring {
			continue
		}
		if _, approved := e.state.Approved[id]; approved {
			continue
		}
		if _, suppressed := e.state.Suppressed[id]; suppressed {
			continue
		}
		if previous, sent := e.recent[id]; sent && ns-previous < int64(e.config.DedupWindow) {
			continue
		}
		if err := e.emit(ns, id, fact); err != nil {
			e.err = err
			return err
		}
		e.recent[id] = ns
	}
	return nil
}

func (e *Engine) emit(ns int64, id string, fact Fact) error {
	detector := "baseline.new-" + fact.Kind
	expected := "fact present in approved baseline"
	severity := "low"
	if fact.Kind == "binding" && fact.Provenance != "dhcp" {
		var conflicting []string
		for _, approved := range e.state.Approved {
			if approved.Kind == "binding" && approved.SrcIP == fact.SrcIP && sameScope(approved.Scope, fact.Scope) && approved.MAC != fact.MAC {
				conflicting = append(conflicting, approved.MAC)
			}
		}
		if len(conflicting) > 0 {
			sort.Strings(conflicting)
			detector, expected, severity = "baseline.address-conflict", conflicting[0], "medium"
			if fact.Provenance == "arp" {
				detector = "baseline.arp-conflict"
			}
		}
	}
	evidence := Evidence{Schema: SchemaVersion, Detector: detector, FactID: id, Observed: fact, Expected: expected,
		Version: e.state.Version, BaselineID: e.state.BaselineID}
	data, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	return e.sink.WriteAlert(&types.Alert{Timestamp: ns, Name: detector, RuleName: detector, Description: "Deviation from approved behavioral baseline",
		SrcIP: fact.SrcIP, DstIP: fact.DstIP, Protocol: fact.Protocol, Severity: severity,
		RecordType: "Behavior", MatchedRecord: string(data), Tags: []string{"behavior", fact.Kind}})
}

func sameScope(a, b Scope) bool {
	aData, _ := json.Marshal(a)
	bData, _ := json.Marshal(b)
	return string(aData) == string(bData)
}

func (e *Engine) Snapshot() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	data, _ := json.Marshal(e.state)
	var snapshot Snapshot
	_ = json.Unmarshal(data, &snapshot)
	if e.err != nil {
		snapshot.Error = e.err.Error()
	} else if source, ok := e.sink.(interface{ Error() error }); ok {
		if err := source.Error(); err != nil {
			snapshot.Error = err.Error()
		}
	}
	return snapshot
}

func (e *Engine) Fail(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.err = errors.Join(e.err, err)
}

// Change records an explicit analyst action and commits it atomically.
// ids are required for approve-changes, suppress and unsuppress.
func (e *Engine) Change(action string, ids []string, reason string) error {
	return e.change(action, ids, reason, nil)
}

func (e *Engine) ChangeAtVersion(action string, ids []string, reason string, version uint64) error {
	return e.change(action, ids, reason, &version)
}

func (e *Engine) change(action string, ids []string, reason string, version *uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return os.ErrClosed
	}
	if e.err != nil {
		return e.err
	}
	if version != nil && *version != e.state.Version {
		return errors.New("baseline version changed; refresh before applying the decision")
	}
	if reason == "" || len(reason) > 1024 || len(ids) > e.config.MaxFacts {
		return errors.New("bounded decision reason is required")
	}
	if len(e.state.Decisions) >= 1000 {
		return errors.New("decision history limit reached; archive the baseline before continuing")
	}
	// Mutate a copy so validation/persistence errors leave the live baseline intact.
	data, err := json.Marshal(e.state)
	if err != nil {
		return err
	}
	var next Snapshot
	if err := json.Unmarshal(data, &next); err != nil {
		return err
	}
	baselineChanged := false
	switch action {
	case "approve":
		if next.Mode != Learning || len(next.Observed) == 0 || next.Samples < next.MinSamples || next.Watermark-next.LearningStarted < next.MinLearningNS || next.Overflow != 0 {
			return errors.New("learning coverage is insufficient or overflowed")
		}
		for id, observation := range next.Observed {
			next.Approved[id] = observation.Fact
		}
		next.Mode = Monitoring
		baselineChanged = true
	case "pause":
		if next.Mode == Paused {
			return errors.New("baseline is already paused")
		}
		next.ResumeMode, next.Mode = next.Mode, Paused
	case "resume":
		if next.Mode != Paused {
			return errors.New("baseline is not paused")
		}
		next.Mode, next.ResumeMode = next.ResumeMode, ""
	case "relearn":
		next.Mode, next.ResumeMode = Learning, ""
		next.LearningStarted, next.Watermark, next.Samples, next.Overflow, next.OutOfOrder = 0, 0, 0, 0, 0
		next.Observed = make(map[string]Observation)
		next.Suppressed = make(map[string]string)
	case "reset":
		next.Mode, next.ResumeMode = Learning, ""
		next.LearningStarted, next.Watermark, next.Samples, next.Overflow, next.OutOfOrder = 0, 0, 0, 0, 0
		next.Observed = make(map[string]Observation)
		next.Approved = make(map[string]Fact)
		next.Suppressed = make(map[string]string)
		baselineChanged = true
	case "approve-changes", "suppress", "unsuppress":
		if next.Mode != Monitoring || len(ids) == 0 {
			return errors.New("monitoring and selected fact IDs are required")
		}
		for _, id := range ids {
			observation, ok := next.Observed[id]
			if !ok {
				return fmt.Errorf("unknown fact %s", id)
			}
			switch action {
			case "approve-changes":
				if _, exists := next.Approved[id]; !exists && len(next.Approved) >= e.config.MaxFacts {
					return errors.New("approved fact limit reached")
				}
				next.Approved[id] = observation.Fact
				delete(next.Suppressed, id)
				baselineChanged = true
			case "suppress":
				next.Suppressed[id] = reason
			case "unsuppress":
				delete(next.Suppressed, id)
			}
		}
	default:
		return fmt.Errorf("unknown baseline action %q", action)
	}
	if baselineChanged {
		next.Version++
		next.BaselineID = baselineID(next.Approved)
	}
	next.Decisions = append(next.Decisions, Decision{At: time.Now().UnixNano(), Action: action, Reason: reason, Version: next.Version, BaselineID: next.BaselineID})
	if err := writeSnapshot(e.config.Path, next); err != nil {
		return err
	}
	e.state = next
	clear(e.recent)
	return nil
}

func baselineID(approved map[string]Fact) string {
	keys := make([]string, 0, len(approved))
	for id := range approved {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	canonical, _ := json.Marshal(keys)
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:])
}

func (e *Engine) Checkpoint() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return os.ErrClosed
	}
	if e.err != nil {
		return e.err
	}
	if source, ok := e.sink.(interface{ Error() error }); ok {
		if err := source.Error(); err != nil {
			e.err = err
			return err
		}
	}
	e.err = writeSnapshot(e.config.Path, e.state)
	return e.err
}

// AddPrefix seeds authoritative prefix metadata at the next capture timestamp.
func (e *Engine) AddPrefix(scope Scope, prefix, provenance string) error {
	scope.VLANs = append([]uint16(nil), scope.VLANs...)
	fact := Fact{Scope: scope, Kind: "prefix", Value: prefix, Provenance: provenance}
	if err := fact.normalize(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return os.ErrClosed
	}
	if len(e.prefixes) >= 256 {
		return errors.New("configured prefix limit reached")
	}
	e.prefixes = append(e.prefixes, fact)
	return nil
}

func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return e.err
	}
	e.closed = true
	e.err = errors.Join(e.err, writeSnapshot(e.config.Path, e.state), e.lease.Close())
	return e.err
}
