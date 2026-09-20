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
	"io"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/pkg/errors"
)

// CollectBPF open the named PCAP file and sets the specified BPF filter.
func (c *Collector) CollectBPF(path, bpf string) error {
	// Recover from any panics during processing
	defer c.recoverFromPanic()

	// open pcap file at path
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return err
	}
	defer handle.Close()

	// set berkeley packet filter on handle
	if err = handle.SetBPFFilter(bpf); err != nil { //nolint:gocritic
		return err
	}

	// initialize collector
	if err = c.Init(); err != nil { //nolint:gocritic
		return err
	}

	stopProgress := c.printProgressInterval()

	c.mu.Lock()
	c.isLive = true
	c.mu.Unlock()

	var (
		data []byte
		ci   gopacket.CaptureInfo
	)

	// read packets
	for {
		// fetch the next packet data and packet header
		data, ci, err = handle.ReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return errors.Wrap(err, errReadingPacketData+" file: "+path)
		}

		if !c.handleRawPacketData(data, &ci) {
			break
		}
	}

	// Stop progress reporting
	stopProgress <- struct{}{}

	// run cleanup on channel exit
	c.cleanup(false)

	return nil
}
