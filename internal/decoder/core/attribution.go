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

package core

import (
	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/internal/reassembly"
)

// Fragment is the read-only view of a stream fragment that a reader needs to
// place a record in time and direction.
//
// It is the exported subset of the unexported fragment interface, so readers
// can take a DataFragments element without restating the whole thing.
type Fragment interface {
	Raw() []byte
	Context() reassembly.AssemblerContext
	Direction() reassembly.TCPFlowDirection
}

// FragmentTime returns the capture time of the packet that carried a fragment,
// in Unix nanoseconds.
//
// Readers used to stamp every record with ConversationInfo.FirstClientPacket.
// That is the time the conversation opened, not the time anything in it
// happened: a connection held open for days collapses to one instant, and no
// question about ordering, rate or a maintenance window survives it.
//
// The assembler context is preferred because it carries the capture time of the
// packet that closed a hole, rather than of the page the fragment sits in.
func FragmentTime(f Fragment) int64 {
	if ctx := f.Context(); ctx != nil {
		return ctx.GetCaptureInfo().Timestamp.UnixNano()
	}

	if ci, ok := f.(interface{ CaptureInfo() gopacket.CaptureInfo }); ok {
		return ci.CaptureInfo().Timestamp.UnixNano()
	}

	return 0
}

// FromServer reports whether a fragment traveled from the server.
func FromServer(f Fragment) bool {
	return f.Direction() == reassembly.TCPDirServerToClient
}

// Endpoints returns the addresses for the direction a fragment traveled in.
//
// Readers used to assign ClientIP to every record unconditionally, which makes
// a response indistinguishable from the command that provoked it: both carry
// the client as their source. A reply belongs to the server.
func (c *ConversationInfo) Endpoints(f Fragment) (srcIP, dstIP string, srcPort, dstPort int32) {
	if FromServer(f) {
		return c.ServerIP, c.ClientIP, c.ServerPort, c.ClientPort
	}

	return c.ClientIP, c.ServerIP, c.ClientPort, c.ServerPort
}

// FragmentIndex maps byte offsets in a concatenated buffer back to the
// fragment each byte arrived in.
//
// Readers that need the whole direction in one slice -- anything with messages
// that span fragments -- lose the per-fragment metadata by concatenating. The
// index keeps it, so a message can still be placed in time and direction by the
// offset of its first byte.
type FragmentIndex struct {
	offsets    []int
	timestamps []int64
	fromServer []bool
}

// Flatten concatenates fragments and returns an index over the result.
func Flatten(fragments DataFragments) ([]byte, *FragmentIndex) {
	idx := &FragmentIndex{}

	size := 0
	for _, f := range fragments {
		size += len(f.Raw())
	}

	data := make([]byte, 0, size)

	for _, f := range fragments {
		raw := f.Raw()
		if len(raw) == 0 {
			continue
		}

		idx.offsets = append(idx.offsets, len(data))
		idx.timestamps = append(idx.timestamps, FragmentTime(f))
		idx.fromServer = append(idx.fromServer, FromServer(f))

		data = append(data, raw...)
	}

	return data, idx
}

// At returns the capture time and direction of the fragment covering offset.
//
// An offset past the end resolves to the last fragment rather than to zero: a
// message whose framing ran off the end still happened, and at the time of the
// bytes that were seen.
func (i *FragmentIndex) At(offset int) (timestamp int64, fromServer bool) {
	if len(i.offsets) == 0 {
		return 0, false
	}

	pos := 0
	for pos+1 < len(i.offsets) && i.offsets[pos+1] <= offset {
		pos++
	}

	return i.timestamps[pos], i.fromServer[pos]
}

// Endpoints returns the addresses for the direction at offset.
func (c *ConversationInfo) EndpointsAt(i *FragmentIndex, offset int) (srcIP, dstIP string, srcPort, dstPort int32) {
	if _, server := i.At(offset); server {
		return c.ServerIP, c.ClientIP, c.ServerPort, c.ClientPort
	}

	return c.ClientIP, c.ServerIP, c.ClientPort, c.ServerPort
}
