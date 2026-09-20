package collector

import (
	"context"
	"errors"
	"time"
)

// ErrStopped is returned when initialization or capture is attempted after Stop.
var ErrStopped = errors.New("collector stopped")

// lifecycleMu must be held when creating the shared cancellation context.
func (c *Collector) contextLocked() context.Context {
	if c.runCtx == nil {
		c.runCtx, c.runCancel = context.WithCancel(context.Background())
	}
	return c.runCtx
}

// A producer must finish before invoking cleanup, which joins all producers.
func (c *Collector) beginCapture() (context.Context, func(), error) {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.lifecycleStopped {
		return nil, nil, ErrStopped
	}
	c.producersWG.Add(1)
	return c.contextLocked(), c.producersWG.Done, nil
}

func (c *Collector) startBackground(run func(context.Context)) {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.lifecycleStopped {
		return
	}
	ctx := c.contextLocked()
	c.backgroundWG.Add(1)
	go func() {
		defer c.backgroundWG.Done()
		run(ctx)
	}()
}

// The producer joins this watcher before releasing its handle or registration.
func interruptCapture(ctx, parent context.Context, closeHandle func()) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			closeHandle()
		case <-parent.Done():
			closeHandle()
		case <-stop:
		}
	}()
	return func() { close(stop); <-done }
}

const defaultLiveReadTimeout = 100 * time.Millisecond

// libpcap Close cannot interrupt an idle read until its configured timeout
// expires. Honor explicit positive values; use a short polling interval when
// callers request an unbounded or otherwise invalid timeout.
func (c *Collector) liveReadTimeout() time.Duration {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.config.Timeout <= 0 {
		return defaultLiveReadTimeout
	}
	return c.config.Timeout
}
