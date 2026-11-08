package firewallaudit

import (
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/responseactions"
	"github.com/gogo/protobuf/proto"
)

type Config struct {
	PolicyFile  string
	EffectsFile string
	Live        bool
	Audit       io.Writer
	// SchemaVersion optionally pins the capability registry used to author rules.
	SchemaVersion string
}

// Result is metadata only. Never add event values, expressions or intent sources.
type Result struct {
	SchemaVersion    string          `json:"schema_version"`
	RecordType       string          `json:"record_type,omitempty"`
	Phase            string          `json:"phase"`
	Decision         policy.Decision `json:"decision"`
	Reason           string          `json:"reason"`
	DryRun           bool            `json:"dry_run"`
	Truncated        bool            `json:"truncated,omitempty"`
	EffectsRequested int             `json:"effects_requested,omitempty"`
	EffectsRejected  int             `json:"effects_rejected,omitempty"`
}

type Runtime struct {
	mu       sync.RWMutex
	closed   bool
	p        *policy.Compiled
	revision string
	effects  map[string][]policy.Effect
	broker   *responseactions.Broker
	version  string
	live     bool
	audit    chan Result
	wg       sync.WaitGroup
	auditErr error
	dropped  atomic.Uint64
}

// Open requires explicit effect admission even for replay, but replay constructs
// no broker. Evaluation uses one counter state with effects removed; only a live,
// attributed winning decision can subsequently be converted to broker intents.
func Open(c Config) (*Runtime, error) {
	registryOnce.Do(initRegistry)
	if c.SchemaVersion != "" && c.SchemaVersion != capabilities.Version {
		return nil, errors.New("firewallaudit: schema version mismatch")
	}
	raw, err := readBounded(c.PolicyFile, policy.MaxBundleBytes)
	if err != nil {
		return nil, err
	}
	b, err := policy.Parse(raw)
	if err != nil {
		return nil, errors.New("firewallaudit: invalid policy document")
	}
	admitted, err := policy.CompileWithOptions(b, policy.CompileOptions{AllowEffects: c.EffectsFile != ""})
	if err != nil {
		return nil, errors.New("firewallaudit: policy compilation failed")
	}
	if err = validateCapabilities(b); err != nil {
		return nil, err
	}
	r := &Runtime{version: capabilities.Version, live: c.Live && c.EffectsFile != "", effects: make(map[string][]policy.Effect), revision: admitted.Revision()}
	for i := range b.Rules {
		r.effects[b.Rules[i].ID] = append([]policy.Effect(nil), b.Rules[i].Effects...)
		b.Rules[i].Effects = nil
	}
	r.p, err = policy.CompileWithOptions(b, policy.CompileOptions{})
	if err != nil {
		return nil, errors.New("firewallaudit: evaluation policy compilation failed")
	}
	if c.EffectsFile != "" {
		cfg, err := LoadConfig(c.EffectsFile)
		if err != nil {
			return nil, err
		}
		if r.live {
			r.broker, err = responseactions.New(cfg)
			if err != nil {
				return nil, errors.New("firewallaudit: broker admission failed")
			}
		}
	}
	if c.Audit != nil {
		r.audit = make(chan Result, 256)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			enc := json.NewEncoder(c.Audit)
			for result := range r.audit {
				if err := enc.Encode(result); err != nil && r.auditErr == nil {
					r.auditErr = errors.New("firewallaudit: audit write failed")
				}
			}
		}()
	}
	return r, nil
}

// Chain preserves a pre-existing observer. Collector.New wraps this callback
// again to retain its own network detection and record analysis.
func (r *Runtime) Chain(previous func(proto.Message)) func(proto.Message) {
	return func(m proto.Message) {
		if previous != nil {
			previous(m)
		}
		r.Observe(m, nil)
	}
}

// Observe is synchronous, bounded projection/evaluation plus nonblocking queue
// admission. There is no per-record goroutine and no writer or network I/O here.
func (r *Runtime) Observe(m proto.Message, packet *PacketContext) Result {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := Result{SchemaVersion: r.version, Phase: "retrospective", DryRun: !r.live}
	if r.closed {
		result.Reason = "closed"
		return result
	}
	p, err := Project(m, packet)
	if err != nil {
		result.Reason = "projection-failed"
	} else {
		result.RecordType, result.Truncated = p.Event.RecordType, p.Truncated
		result.Decision, err = r.p.Evaluate(p.Event)
		result.Decision.Revision = r.revision
		if err != nil {
			result.Reason = "evaluation-failed"
		} else {
			result.Reason = "bundle-default"
			if result.Decision.RuleID != "" {
				result.Reason = "rule-matched"
			}
			if r.live && !result.Decision.Monitor && len(r.effects[result.Decision.RuleID]) > 0 {
				if p.Event.Network.SrcIP == "" {
					result.Reason = "source-unavailable"
				} else {
					r.dispatch(&result, p.Event.Network.SrcIP)
				}
			}
		}
	}
	if r.audit != nil {
		select {
		case r.audit <- result:
		default:
			r.dropped.Add(1)
		}
	}
	return result
}

func (r *Runtime) dispatch(result *Result, source string) {
	now := time.Now().UTC()
	for _, effect := range r.effects[result.Decision.RuleID] {
		ttl, _ := time.ParseDuration(effect.Duration) // already admitted by policy compiler
		i := policy.Intent{Kind: effect.Kind, Target: effect.Target, Source: source, Scope: effect.Scope, Revision: r.revision, RuleID: result.Decision.RuleID, TTL: ttl, IssuedAt: now, ExpiresAt: now.Add(ttl)}
		i.ID = policy.IntentID(i)
		receipt := r.broker.Submit(i, source)
		if receipt.Status == "requested" {
			result.EffectsRequested++
		} else if receipt.Status != "duplicate" {
			result.EffectsRejected++
			result.Reason = "effect-rejected"
		}
	}
}

func (r *Runtime) DroppedAudit() uint64 { return r.dropped.Load() }

// Receipts reports asynchronous broker outcomes without record or source values.
func (r *Runtime) Receipts() []responseactions.Receipt {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.broker == nil {
		return nil
	}
	return r.broker.Receipts()
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		if r.audit != nil {
			close(r.audit)
			r.wg.Wait()
		}
		if r.broker != nil {
			_ = r.broker.Close()
		}
	}
	if r.dropped.Load() > 0 {
		return errors.Join(r.auditErr, errors.New("firewallaudit: audit queue overflow"))
	}
	return r.auditErr
}
