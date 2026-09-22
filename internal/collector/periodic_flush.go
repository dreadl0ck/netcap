/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package collector

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// startPeriodicFlush starts a goroutine that periodically flushes all decoders.
// This makes audit records visible during live capture without waiting for shutdown.
// Returns a channel to stop the goroutine.
func (c *Collector) startPeriodicFlush() chan struct{} {
	stopChan := make(chan struct{})

	if c.config.LiveFlushInterval <= 0 {
		// Periodic flushing disabled
		return stopChan
	}

	c.startBackground(func(ctx context.Context) {
		c.log.Info("starting periodic flush",
			zap.Duration("interval", c.config.LiveFlushInterval),
		)

		ticker := time.NewTicker(c.config.LiveFlushInterval)

		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopChan:
				return
			case <-ticker.C:
				c.flushAllDecoders()
			}
		}
	})

	return stopChan
}

// flushAllDecoders flushes all decoder writers and writes current state of accumulating decoders.
// This is called periodically during live capture to make data visible.
func (c *Collector) flushAllDecoders() {
	c.statMutex.Lock()
	if c.shutdown {
		// Don't flush during shutdown - cleanup will handle it
		c.statMutex.Unlock()
		return
	}
	c.statMutex.Unlock()

	start := time.Now()
	var totalFlushed int64

	// Flush gopacket decoders (they write records immediately, just flush buffers)
	for _, decoders := range c.goPacketDecoders {
		for _, dec := range decoders {
			dec.FlushCurrentState()
		}
	}

	// Flush packet decoders (includes accumulating decoders like DeviceProfile, IPProfile, Connection)
	for _, dec := range c.packetDecoders {
		numFlushed := dec.FlushCurrentState()
		totalFlushed += numFlushed
	}

	// Flush stream decoders
	for _, dec := range c.streamDecoders {
		dec.FlushCurrentState()
	}

	// Flush abstract decoders
	for _, dec := range c.abstractDecoders {
		dec.FlushCurrentState()
	}

	c.log.Debug("periodic flush completed",
		zap.Duration("duration", time.Since(start)),
		zap.Int64("accumulating_records_flushed", totalFlushed),
	)

	if !c.config.DecoderConfig.Quiet {
		c.printlnStdOut("flushed audit records in", time.Since(start))
	}
}
