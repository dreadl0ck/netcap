package firewallstate

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/runtimeobs"
)

// GuardConfig is runtime configuration, separate from native policy thresholds.
// The remote principal owns tenant/app scope. GroupBy supports only these bounded
// scalar fields: empty (global), ClientIP, Host, Method, Path.
// Unit defaults to request; message counts only request-phase inspection messages.
type GuardConfig struct {
	URL     string        `json:"url"`
	Token   string        `json:"token"`
	Window  time.Duration `json:"window"`
	Limit   int64         `json:"limit"`
	GroupBy string        `json:"group_by"`
	ID      string        `json:"id"`
	Unit    string        `json:"unit,omitempty"`
}
type Guard struct {
	Operations *runtimeobs.Monitor
	cfg        GuardConfig
	store      Store
	mu         sync.RWMutex
	lastErr    error
	contacted  bool
	operation  uint64
}

type healthStore interface{ Probe(context.Context) error }

func (g *Guard) beginOperation() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.operation++
	return g.operation
}
func (g *Guard) finishOperation(operation uint64, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if operation == g.operation {
		g.lastErr = err
		g.contacted = true
		condition := "ok"
		if err != nil {
			condition = "state_unavailable"
		}
		g.Operations.Health(err == nil, condition)
	}
}

// Probe checks authoritative availability without consuming quota. A stale
// completion cannot overwrite the result of an operation started later.
func (g *Guard) Probe(ctx context.Context) error {
	operation := g.beginOperation()
	store, ok := g.store.(healthStore)
	var err error
	if !ok {
		err = errors.New("store cannot probe")
	} else {
		err = store.Probe(ctx)
	}
	g.finishOperation(operation, err)
	return err
}

func NewGuard(cfg GuardConfig) (*Guard, error) {
	c, err := NewClient(ClientConfig{URL: cfg.URL, Token: cfg.Token})
	if err != nil {
		return nil, err
	}
	return NewGuardWithStore(cfg, c)
}
func NewGuardWithStore(cfg GuardConfig, store Store) (*Guard, error) {
	if cfg.Unit == "" {
		cfg.Unit = "request"
	}
	if cfg.Unit != "request" && cfg.Unit != "message" {
		return nil, errors.New("unit must be request or message")
	}
	if store == nil || !ValidID(cfg.ID) || cfg.Limit < 1 || cfg.Window < time.Millisecond || cfg.Window > MaxWindow {
		return nil, errors.New("invalid shared guard configuration")
	}
	switch cfg.GroupBy {
	case "", "ClientIP", "Host", "Method", "Path":
	default:
		return nil, errors.New("unsupported group_by")
	}
	return &Guard{Operations: runtimeobs.New("guard"), cfg: cfg, store: store}, nil
}

// Ready reports ordered count/probe outcomes; no contact is unready.
func (g *Guard) Ready() (bool, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.contacted {
		return false, errors.New("shared state has not been contacted")
	}
	return g.lastErr == nil, g.lastErr
}

func (g *Guard) Evaluate(ctx context.Context, c *policy.Compiled, e policy.Event) (policy.Decision, error) {
	rev := ""
	if c != nil {
		rev = c.Revision()
	}
	deny := policy.Decision{Verdict: "deny", Status: 503, RuleID: g.cfg.ID, Revision: rev}
	if c == nil {
		return deny, errors.New("policy uninitialized")
	}
	count := false
	if e.Phase != "response" {
		switch e.Attributes["inspection.kind"] {
		case "", "headers":
			count = g.cfg.Unit == "request"
		case "message":
			count = g.cfg.Unit == "message"
		case "trailers":
		default:
			return deny, errors.New("unsupported inspection.kind")
		}
	}
	if !count {
		d, err := c.Evaluate(e)
		if err != nil {
			return deny, err
		}
		return d, nil
	}
	v := ""
	switch g.cfg.GroupBy {
	case "ClientIP":
		v = e.ClientIP
	case "Host":
		v = e.Host
	case "Method":
		v = e.Method
	case "Path":
		v = e.Path
	}
	if len(v) > 65536 {
		return deny, errors.New("group exceeds limit")
	}
	// Include rule configuration to isolate independent guards even on one revision.
	k := Key{Revision: rev, Group: Digest(g.cfg.ID + "\x00" + g.cfg.Unit + "\x00" + g.cfg.GroupBy + "\x00" + v)}
	operation := g.beginOperation()
	start := time.Now()
	out, err := g.store.Count(ctx, k, Window{Mode: "fixed", Duration: g.cfg.Window}, time.Now())
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	g.Operations.Observe("state", start, outcome)
	g.finishOperation(operation, err)
	if err != nil {
		return deny, err
	}
	if out.Count > g.cfg.Limit {
		deny.Status = 429
		return deny, nil
	}
	d, err := c.Evaluate(e)
	if err != nil {
		return deny, err
	}
	return d, nil
}
