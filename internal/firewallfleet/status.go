package firewallfleet

import (
	"context"
	"errors"
	"sync"
	"time"
)

// One mutex orders network updates, expiry, and callbacks. Close joins the
// watchdog and waits for any callback, so publication cannot outlive Run.
type agentPublisher struct {
	ctx      context.Context
	mu       sync.Mutex
	status   AgentStatus
	contact  time.Time
	expires  time.Time
	maxStale time.Duration
	callback func(AgentStatus)
	closed   bool
	wake     chan struct{}
	stop     chan struct{}
	done     chan struct{}
}

func newAgentPublisher(ctx context.Context, cfg AgentConfig) *agentPublisher {
	p := &agentPublisher{ctx: ctx, maxStale: cfg.MaxStale, callback: cfg.OnStatus, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	if cfg.MaxStale > 0 {
		go p.watch()
	} else {
		close(p.done)
	}
	return p
}

func (p *agentPublisher) publish(status AgentStatus, durable bool, contact time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil {
		return
	}
	if !contact.Equal(p.contact) {
		p.contact = contact
		// Online contact retains its monotonic clock. A cached wall-clock age is
		// converted once to a monotonic deadline and never extended by errors.
		age := time.Since(contact)
		if age < 0 {
			age = 0
		}
		p.expires = time.Now().Add(p.maxStale - age)
	}
	status.Ready = durable && status.Generation > 0 && !status.Draining && !status.Revoked && (p.maxStale == 0 || !contact.IsZero() && time.Now().Before(p.expires))
	if !status.Ready && durable && status.Generation > 0 && !status.Draining && !status.Revoked && status.Error == "" {
		status.Error = "last-known policy stale"
	}
	p.status = status
	if p.ctx.Err() != nil {
		return
	}
	p.callback(status)
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *agentPublisher) watch() {
	defer close(p.done)
	for {
		p.mu.Lock()
		active := p.status.Ready && !p.closed
		delay := time.Until(p.expires)
		p.mu.Unlock()
		if !active {
			select {
			case <-p.stop:
				return
			case <-p.wake:
				continue
			}
		}
		timer := time.NewTimer(max(delay, 0))
		select {
		case <-p.stop:
			timer.Stop()
			return
		case <-p.wake:
			timer.Stop()
			continue
		case <-timer.C:
			p.mu.Lock()
			if !p.closed && p.ctx.Err() == nil && p.status.Ready && !time.Now().Before(p.expires) {
				p.status.Ready = false
				if p.status.Error == "" {
					p.status.Error = "last-known policy stale"
				}
				if p.ctx.Err() == nil {
					p.callback(p.status)
				}
			}
			p.mu.Unlock()
		}
	}
}

func (p *agentPublisher) close() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.stop)
		p.status.Ready = false
		p.status.Error = "agent stopped"
		if err := p.ctx.Err(); errors.Is(err, context.DeadlineExceeded) {
			p.status.Error = context.DeadlineExceeded.Error()
		} else if err != nil {
			p.status.Error = context.Canceled.Error()
		}
		p.callback(p.status)
	}
	p.mu.Unlock()
	<-p.done
}
