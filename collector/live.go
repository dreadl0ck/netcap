//go:build !linux

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
	"io"

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
	runCtx, finish, err := c.beginCapture()
	if err != nil {
		return err
	}
	defer c.cleanup(false)
	defer finish()

	// open interface in live mode
	// snaplen, promiscuous mode and the timeout value can be configured over the collector instance
	handle, err := pcap.OpenLive(iface, int32(c.config.SnapLen), c.config.Promisc, c.liveReadTimeout())
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
	defer interruptCapture(runCtx, ctx, handle.Close)()

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
		case <-runCtx.Done():
			goto done
		case <-ctx.Done():
			goto done
		default:

			// read next packet
			data, ci, err = handle.ReadPacketData()
			if err != nil {
				if errors.Is(err, io.EOF) {
					goto done
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

			if !c.handleRawPacketData(data, &ci) {
				goto done
			}
		}
	}

done:

	// Stop progress reporting
	close(stopProgress)

	// Stop periodic flushing
	close(stopPeriodicFlush)

	return nil
}
