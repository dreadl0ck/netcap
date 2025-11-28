//go:build !linux
// +build !linux

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
	"fmt"
	"io"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/pkg/errors"
)

// CollectLive starts collection of data from the given interface
// optionally a bpf can be supplied.
// this is the darwin version that uses the pcap lib with c bindings to fetch packets
// currently there is no other option to do that.
func (c *Collector) CollectLive(iface, bpf string, ctx context.Context) error {
	// Recover from any panics during processing
	defer c.recoverFromPanic()

	// open interface in live mode
	// snaplen, promiscuous mode and the timeout value can be configured over the collector instance
	handle, err := pcap.OpenLive(iface, int32(c.config.SnapLen), c.config.Promisc, c.config.Timeout)
	if err != nil {
		return err
	}
	// close handle on exit
	defer handle.Close()

	// set BPF if requested
	if bpf != "" {
		err = handle.SetBPFFilter(bpf)
		if err != nil {
			return err
		}
	}

	if err = c.handleLinkType(handle.LinkType()); err != nil {
		return err
	}

	// initialize collector
	if err = c.Init(); err != nil {
		return err
	}

	stopProgress := c.printProgressInterval()
	stopPeriodicFlush := c.startPeriodicFlush()

	c.mu.Lock()
	c.isLive = true
	c.mu.Unlock()

	var (
		data []byte
		ci   gopacket.CaptureInfo
	)

	// read packets from channel
	for {
		select {
		case <-ctx.Done():
			fmt.Println("live capture canceled via context")
			goto done
		default:

			// read next packet
			data, ci, err = handle.ReadPacketData()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}

				// Check if shutdown has been initiated (e.g., via signal handler)
				c.statMutex.Lock()
				isShutdown := c.shutdown
				c.statMutex.Unlock()

				// If cleanup is already in progress, exit gracefully
				if isShutdown {
					goto done
				}

				// Pcap timeouts are expected during live capture when no packets arrive
				// within the timeout period. Just continue reading.
				if err.Error() == "Timeout Expired" {
					continue
				}

				// For other errors, perform cleanup and return the error
				goto done
			}

			// increment atomic packet counter
			atomic.AddInt64(&c.current, 1)

			// must be locked, otherwise a race occurs when sending a SIGINT
			//  and triggering wg.Wait() in another goroutine...
			c.statMutex.Lock()

			// increment wait group for packet processing
			c.wg.Add(1)

			c.statMutex.Unlock()

			c.handleRawPacketData(data, &ci)
		}
	}

done:

	// Stop progress reporting
	stopProgress <- struct{}{}

	// Stop periodic flushing
	close(stopPeriodicFlush)

	// Check if cleanup is already in progress (e.g., triggered by signal handler)
	c.statMutex.Lock()
	isShutdown := c.shutdown
	c.statMutex.Unlock()

	// Only run cleanup if it hasn't been triggered yet
	// If shutdown is already true, cleanup is being handled elsewhere (e.g., signal handler)
	if !isShutdown {
		c.cleanup(false)
	}

	return nil
}
