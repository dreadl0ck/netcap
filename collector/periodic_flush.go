/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package collector

import (
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

	c.log.Info("starting periodic flush",
		zap.Duration("interval", c.config.LiveFlushInterval),
	)

	ticker := time.NewTicker(c.config.LiveFlushInterval)

	go func() {
		for {
			select {
			case <-stopChan:
				ticker.Stop()
				return
			case <-ticker.C:
				c.flushAllDecoders()
			}
		}
	}()

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

