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

// Package network handles network-layer protocol conversations (ICMP, IGMP, GRE, etc.)
// that don't have a transport layer. Conversations are grouped by IP pair.
package network

import (
	"sort"
	"sync"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/reassembly"
)

// Streams contains a pool of network-layer data streams
var Streams = newNetworkStreamPool()

// ResetStreams creates a new network stream pool to clear all stream state
// This should be called when resetting state between processing different files
func ResetStreams() {
	Streams = newNetworkStreamPool()
}

// NetworkData represents a single network-layer packet fragment
type NetworkData struct {
	// Raw payload data from the network layer
	RawData []byte

	// Capture information from gopacket
	CaptureInformation gopacket.CaptureInfo

	// Network layer flow (src/dst IP)
	Net gopacket.Flow

	// Protocol type (e.g., "ICMPv4", "ICMPv6", "IGMP", "GRE")
	Protocol string

	// Direction of the packet (client to server or server to client)
	Dir reassembly.TCPFlowDirection
}

// Raw returns the raw byte slice that makes up the data fragment.
func (n *NetworkData) Raw() []byte {
	return n.RawData
}

// CaptureInfo returns the capture information from gopacket
func (n *NetworkData) CaptureInfo() gopacket.CaptureInfo {
	return n.CaptureInformation
}

// Network returns the network layer flow
func (n *NetworkData) Network() gopacket.Flow {
	return n.Net
}

// Direction returns the direction of the packet
func (n *NetworkData) Direction() reassembly.TCPFlowDirection {
	return n.Dir
}

// SetDirection sets the direction of the packet
func (n *NetworkData) SetDirection(d reassembly.TCPFlowDirection) {
	n.Dir = d
}

// NetworkDataFragments is a sortable slice of NetworkData
type NetworkDataFragments []*NetworkData

// Len returns the length of the fragments
func (n NetworkDataFragments) Len() int {
	return len(n)
}

// Less compares two fragments by timestamp
func (n NetworkDataFragments) Less(i, j int) bool {
	return n[i].CaptureInformation.Timestamp.Before(n[j].CaptureInformation.Timestamp)
}

// Swap swaps two fragments
func (n NetworkDataFragments) Swap(i, j int) {
	n[i], n[j] = n[j], n[i]
}

// Size returns the total size of all fragments
func (n NetworkDataFragments) Size() int {
	var size int
	for _, d := range n {
		size += len(d.RawData)
	}
	return size
}

// Sort sorts the fragments by timestamp
func (n NetworkDataFragments) Sort() {
	sort.Sort(n)
}

// networkStream represents a network-layer conversation between two IPs
type networkStream struct {
	sync.Mutex
	data     NetworkDataFragments
	protocol string // Primary protocol of the conversation
}

// networkStreamPool holds a pool of network streams
type networkStreamPool struct {
	sync.Mutex
	streams map[uint64]*networkStream
}

func newNetworkStreamPool() *networkStreamPool {
	return &networkStreamPool{
		streams: make(map[uint64]*networkStream),
	}
}

func (p *networkStreamPool) size() int {
	p.Lock()
	defer p.Unlock()
	return len(p.streams)
}

// HandleNetworkPacket takes a network-layer packet without transport layer and tracks it
func (p *networkStreamPool) HandleNetworkPacket(packet gopacket.Packet, payload []byte, protocol string) {
	nl := packet.NetworkLayer()
	if nl == nil {
		return
	}

	// Use network flow hash as the stream key (bidirectional)
	flowHash := nl.NetworkFlow().FastHash()

	p.Lock()
	if s, ok := p.streams[flowHash]; ok {
		p.Unlock()

		s.Lock()
		s.data = append(s.data, &NetworkData{
			RawData:            payload,
			CaptureInformation: packet.Metadata().CaptureInfo,
			Net:                nl.NetworkFlow(),
			Protocol:           protocol,
		})
		s.Unlock()
	} else {
		// Create new stream
		str := &networkStream{
			protocol: protocol,
		}
		str.data = append(str.data, &NetworkData{
			RawData:            payload,
			CaptureInformation: packet.Metadata().CaptureInfo,
			Net:                nl.NetworkFlow(),
			Protocol:           protocol,
		})
		p.streams[flowHash] = str
		p.Unlock()
	}
}

// GetFirstPacketTime returns the timestamp of the first packet in the stream
func (s *networkStream) GetFirstPacketTime() time.Time {
	if len(s.data) == 0 {
		return time.Time{}
	}
	return s.data[0].CaptureInformation.Timestamp
}

