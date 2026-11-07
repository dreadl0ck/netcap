package collector

import (
	"context"
	"time"
)

func (c *Collector) startLiveMaintenance() chan struct{} {
	stop := make(chan struct{})
	interval := c.config.LiveMaintenanceInterval
	if interval < 0 || !c.config.ReassembleConnections {
		return stop
	}
	if interval == 0 {
		interval = time.Second
	}
	c.startBackground(func(ctx context.Context) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case ref := <-ticker.C:
				c.maintainStreams(ref)
			}
		}
	})
	return stop
}

func (c *Collector) maintainStreams(ref time.Time) {
	c.dispatchMu.Lock()
	defer c.dispatchMu.Unlock()
	if !c.acceptingPackets || c.workersStopped {
		return
	}
	for _, worker := range c.workers {
		worker <- &workerControl{ref: ref, idle: true}
	}
}
