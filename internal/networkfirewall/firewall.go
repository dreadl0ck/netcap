// Package networkfirewall implements a routed, verdict-producing packet firewall.
// It does not decrypt TLS or modify packet bytes.
package networkfirewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/internal/runtimeobs"
)

type Verdict string

const (
	Allow     Verdict = "allow"
	Deny      Verdict = "deny"
	WouldDeny Verdict = "would-deny"
)

type PacketEvent struct {
	SrcIP, DstIP        string
	SrcPort, DstPort    int
	Transport           string
	IPVersion, TCPFlags int
	Direction           string
	TLS                 *TLSMetadata
}

type Decision struct{ Verdict Verdict }

// Evaluator must be safe to retain until its outstanding call finishes. Only one
// call runs at a time; a hung evaluator consumes one worker, never one per packet.
type Evaluator interface {
	EvaluatePacket(PacketEvent) (Decision, error)
}

type Config struct {
	Namespace, Interface string
	ProtectedCIDRs       []string
	// ManagementDestinations exempts these peer CIDRs in both flow directions.
	ManagementDestinations []string
	Hook                   string // input or forward
	Queue                  uint16
	MaxQueueLen            uint32
	Deadline               time.Duration
	FailureVerdict         Verdict
	// BypassWithoutListener and FailOpenOnOverflow are independent kernel policies.
	BypassWithoutListener, FailOpenOnOverflow bool
	// InspectTLS enables bounded visible ClientHello metadata; it never holds a
	// packet waiting for a later segment and cannot inspect encrypted application data.
	InspectTLS bool
}

type Counters struct{ Packets, Accepted, Dropped, WouldDeny, ParseErrors, EvaluationErrors, Deadlines, Overloads, VerdictErrors, ReceiveErrors uint64 }

type Firewall struct {
	Operations *runtimeobs.Monitor
	config     Config
	protected  []netip.Prefix
	evaluator  Evaluator
	ready      chan struct{}
	started    atomic.Bool
	counts     [10]atomic.Uint64
	tls        *helloInspector
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$`)

func New(c Config, e Evaluator) (*Firewall, error) {
	if !identifier.MatchString(c.Namespace) || c.Namespace == "default" || !identifier.MatchString(c.Interface) || len(c.Interface) > 15 || c.Interface == "lo" {
		return nil, errors.New("explicit non-default named namespace and non-loopback interface required")
	}
	if c.Hook != "input" && c.Hook != "forward" {
		return nil, errors.New("hook must explicitly be input or forward")
	}
	if c.FailureVerdict != Allow && c.FailureVerdict != Deny {
		return nil, errors.New("failure verdict must explicitly be allow or deny")
	}
	if c.MaxQueueLen == 0 || c.MaxQueueLen > 65535 || c.Deadline <= 0 || c.Deadline > time.Second {
		return nil, errors.New("max queue must be 1..65535 and deadline (0,1s]")
	}
	if len(c.ProtectedCIDRs) == 0 || e == nil {
		return nil, errors.New("protected CIDRs and evaluator required")
	}
	c.ProtectedCIDRs = append([]string(nil), c.ProtectedCIDRs...)
	c.ManagementDestinations = append([]string(nil), c.ManagementDestinations...)
	f := &Firewall{Operations: runtimeobs.New("network"), config: c, evaluator: e, ready: make(chan struct{})}
	if c.InspectTLS {
		f.tls = newHelloInspector()
	}
	for _, s := range append(append([]string(nil), c.ProtectedCIDRs...), c.ManagementDestinations...) {
		if _, err := netip.ParsePrefix(s); err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
	}
	for _, s := range c.ProtectedCIDRs {
		p, _ := netip.ParsePrefix(s)
		f.protected = append(f.protected, p)
	}
	return f, nil
}

// Ready closes after both the queue listener and scoped diversion rules exist.
func (f *Firewall) Ready() <-chan struct{} { return f.ready }

func (f *Firewall) Stats() Counters {
	return Counters{f.counts[0].Load(), f.counts[1].Load(), f.counts[2].Load(), f.counts[3].Load(), f.counts[4].Load(), f.counts[5].Load(), f.counts[6].Load(), f.counts[7].Load(), f.counts[8].Load(), f.counts[9].Load()}
}

type evaluation struct {
	event  PacketEvent
	result chan evaluationResult
}
type evaluationResult struct {
	decision Decision
	err      error
}

func evaluate(e Evaluator, event PacketEvent) (r evaluationResult) {
	defer func() {
		if p := recover(); p != nil {
			r.err = fmt.Errorf("evaluator panic: %v", p)
		}
	}()
	r.decision, r.err = e.EvaluatePacket(event)
	return
}

func (f *Firewall) worker(ctx context.Context) chan evaluation {
	jobs := make(chan evaluation)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case job := <-jobs:
				job.result <- evaluate(f.evaluator, job.event)
			}
		}
	}()
	return jobs
}

func (f *Firewall) decide(ctx context.Context, jobs chan evaluation, raw []byte) (verdict Verdict) {
	start := time.Now()
	defer func() { f.Operations.Observe("decision", start, string(verdict)) }()
	f.counts[0].Add(1)
	e, err := ParsePacket(raw)
	if err != nil {
		f.counts[4].Add(1)
		f.Operations.Health(false, "evaluation_failed")
		return f.config.FailureVerdict
	}
	if f.tls != nil && e.Transport == "tcp" {
		e.TLS = f.tls.observe(raw, e, time.Now())
	}
	e.Direction = "inbound"
	src, _ := netip.ParseAddr(e.SrcIP)
	for _, p := range f.protected {
		if p.Contains(src) {
			e.Direction = "outbound"
			break
		}
	}
	job := evaluation{e, make(chan evaluationResult, 1)}
	timer := time.NewTimer(f.config.Deadline)
	defer timer.Stop()
	select {
	case jobs <- job:
		f.Operations.Observe("queue", start, "ok")
	case <-ctx.Done():
		return f.config.FailureVerdict
	case <-timer.C:
		f.counts[7].Add(1)
		f.Operations.Observe("queue", start, "timeout")
		f.Operations.Health(false, "capacity")
		return f.config.FailureVerdict
	}
	select {
	case r := <-job.result:
		if r.err != nil {
			f.counts[5].Add(1)
			f.Operations.Health(false, runtimeobs.NativeFailure(r.err))
			return f.config.FailureVerdict
		}
		f.Operations.Health(true, "ok")
		switch r.decision.Verdict {
		case Allow, Deny:
			return r.decision.Verdict
		case WouldDeny:
			f.counts[3].Add(1)
			return Allow
		default:
			f.counts[5].Add(1)
			return f.config.FailureVerdict
		}
	case <-ctx.Done():
		return f.config.FailureVerdict
	case <-timer.C:
		f.counts[6].Add(1)
		f.Operations.Health(false, "deadline")
		return f.config.FailureVerdict
	}
}
