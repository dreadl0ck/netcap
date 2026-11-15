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

package udp

import (
	"reflect"
	"sync"
	"time"

	"github.com/gopacket/gopacket"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/service"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/internal/sipaudit"
	"github.com/dreadl0ck/netcap/internal/utils"
)

// Streams contains a pool of UDP data streams
var Streams = newUDPStreamPool()

// ResetStreams creates a new UDP stream pool to clear all stream state
// This should be called when resetting state between processing different files
func ResetStreams() {
	Streams = newUDPStreamPool()
}

// udpData represents a udp data stream.
type udpStream struct {
	refused bool
	sync.Mutex
	data    core.DataFragments
	decoder core.StreamDecoderInterface
	scope   string
}

// udpStreamPool holds a pool of UDP streams.
type udpStreamPool struct {
	sync.Mutex
	streams map[uint64]*udpStream
}

func newUDPStreamPool() *udpStreamPool {
	return &udpStreamPool{
		streams: make(map[uint64]*udpStream),
	}
}

func (u *udpStreamPool) size() int {
	u.Lock()
	defer u.Unlock()

	return len(u.streams)
}

// udpConversationKey identifies a UDP conversation by both endpoints.
// Keying on the transport flow alone merged every conversation that happened
// to share a port pair, e.g. all DNS traffic towards port 53, regardless of
// the hosts involved. FastHash collides with the reverse flow by design, so
// both directions still map to the same conversation.
func udpConversationKey(packet gopacket.Packet) uint64 {
	key := packet.TransportLayer().TransportFlow().FastHash()
	if net := packet.NetworkLayer(); net != nil {
		key ^= net.NetworkFlow().FastHash()
	}

	return key ^ packetview.ScopeHash(packet)
}

// HandleUDP takes an UDP packet and tracks the data seen for the conversation.
func (u *udpStreamPool) HandleUDP(packet gopacket.Packet, udpLayer gopacket.Layer) {
	// Signaling is needed even when only RTP/DTMF output was selected. Observe
	// it before the EOF UDP drain, independently of the SIP audit writer.
	if wire, _, err := sipaudit.Parse(udpLayer.LayerPayload(), false); err == nil {
		msg := sipaudit.Record(wire, packet.Metadata().Timestamp.UnixNano())
		msg.NetworkScope = packetview.Scope(packet)
		sipaudit.Media.Observe(msg)
	}
	key := udpConversationKey(packet)

	u.Lock()
	if s, ok := u.streams[key]; ok {
		u.Unlock()

		s.Lock()
		s.data = append(s.data, &core.StreamData{
			RawData:            udpLayer.LayerPayload(),
			CaptureInformation: packet.Metadata().CaptureInfo,
			Trans:              packet.TransportLayer().TransportFlow(),
			Net:                packet.NetworkLayer().NetworkFlow(),
		})
		s.Unlock()
	} else {
		// add new
		str := new(udpStream)
		str.scope = packetview.Scope(packet)
		str.data = append(str.data, &core.StreamData{
			RawData:            udpLayer.LayerPayload(),
			CaptureInformation: packet.Metadata().CaptureInfo,
			Trans:              packet.TransportLayer().TransportFlow(),
			Net:                packet.NetworkLayer().NetworkFlow(),
		})
		u.streams[key] = str
		u.Unlock()
	}
}

// saves the banner for a UDP service to the filesystem
// and limits the length of the saved data to the BannerSize value from the config.
func saveUDPServiceBanner(banner []byte, flowIdent string, serviceIdent string, firstPacket time.Time, serverBytes int, clientBytes int, net gopacket.Flow, transport gopacket.Flow) {
	// limit length of data
	if len(banner) >= decoderconfig.Instance.BannerSize {
		banner = banner[:decoderconfig.Instance.BannerSize]
	}

	created, _ := service.ObserveFlowBanner(serviceIdent, flowIdent, banner, firstPacket, serverBytes, clientBytes, net, transport, "UDP")
	if created {
		streamutils.Stats.Lock()
		streamutils.Stats.NumServices++
		streamutils.Stats.Unlock()
	}
}

// TODO: ensure that only decoders of protocols are called that actually support being transported via UDP
// TODO: specify transport protocols during decoder creation
func (u *udpStream) decode() {
	// choose the decoder to run against the data stream
	var (
		cr                []byte
		sr                []byte
		clientFirstPacket time.Time
		serverFirstReply  time.Time
	)

	// first message defines the client
	clientNetwork, clientTransport := clientFlows(u.data)

	// search for the first server reply
	for _, d := range u.data {
		if d.Transport() == clientTransport && d.Network() == clientNetwork {
			if cr == nil {
				cr = d.Raw()
				clientFirstPacket = d.CaptureInfo().Timestamp
			}
		} else if sr == nil {
			sr = d.Raw()
			serverFirstReply = d.CaptureInfo().Timestamp
		}
	}

	// set directions for all fragments
	// TODO: this is a bit of a hack, since we are reusing the constants from the TCP reassembly
	// TODO: add generic stream direction types in netcap and use those in the readers Decode() implementations instead
	for _, d := range u.data {
		if d.Transport() == clientTransport && d.Network() == clientNetwork {
			// client
			d.SetDirection(reassembly.TCPDirClientToServer)
		} else {
			// server
			d.SetDirection(reassembly.TCPDirServerToClient)
		}
	}

	conv := &core.ConversationInfo{
		Transport:         core.UDP,
		NetworkScope:      u.scope,
		Data:              u.data,
		Ident:             utils.CreateFlowIdentFromLayerFlows(clientNetwork, clientTransport),
		FirstClientPacket: clientFirstPacket,
		FirstServerPacket: serverFirstReply,
		ClientIP:          clientNetwork.Src().String(),
		ServerIP:          clientNetwork.Dst().String(),
		ClientPort:        utils.DecodePort(clientTransport.Src().Raw()),
		ServerPort:        utils.DecodePort(clientTransport.Dst().Raw()),
		CommunityID: streamutils.CalcCommunityIDUDP(
			u.data[0].Network().Src().String(),
			u.data[0].Network().Dst().String(),
			uint16(utils.DecodePort(u.data[0].Transport().Src().Raw())),
			uint16(utils.DecodePort(u.data[0].Transport().Dst().Raw())),
		),
	}

	// A later datagram can identify a conversation whose first one was noise.
	// Evaluate each UDP message separately; concatenating them would fabricate
	// a payload that was never sent.
	datagrams := make([]stream.Datagram, 0, len(u.data))
	for _, d := range u.data {
		datagrams = append(datagrams, stream.Datagram{
			Data: d.Raw(), Client: d.Direction() == reassembly.TCPDirClientToServer,
		})
	}
	if sel, found := stream.SelectDecoder(&stream.SelectionInput{
		Transport:    core.UDP,
		ServerPort:   utils.DecodePort(clientTransport.Dst().Raw()),
		PortClient:   cr,
		PortServer:   sr,
		ScanClient:   cr,
		ScanServer:   sr,
		Datagrams:    datagrams,
		Conversation: conv,
	}); found {
		u.decoder = sel.Decoder
	}

	// call the decoder if one was found
	if u.decoder != nil {
		ti := time.Now()

		// call the associated decoder
		u.decoder.Decode()

		udpStreamDecodeTime.WithLabelValues(reflect.TypeOf(u.decoder).String()).Set(float64(time.Since(ti).Nanoseconds()))
	}
}

// NumSavedUDPConns returns the number of saved UDP conversations.
func NumSavedUDPConns() int64 {
	streamutils.Stats.Lock()
	defer streamutils.Stats.Unlock()

	return streamutils.Stats.SavedUDPConnections
}
