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

package udp

import (
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/dreadl0ck/gopacket"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream"
	"github.com/dreadl0ck/netcap/decoder/stream/service"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

// Streams contains a pool of UDP data streams
var Streams = newUDPStreamPool()

const typeUDP = "udp"

// udpData represents a udp data stream.
type udpStream struct {
	sync.Mutex
	data    core.DataFragments
	decoder core.StreamDecoderInterface
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

// HandleUDP takes an UDP packet and tracks the data seen for the conversation.
func (u *udpStreamPool) HandleUDP(packet gopacket.Packet, udpLayer gopacket.Layer) {
	u.Lock()
	if s, ok := u.streams[packet.TransportLayer().TransportFlow().FastHash()]; ok {
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
		str.data = append(str.data, &core.StreamData{
			RawData:            udpLayer.LayerPayload(),
			CaptureInformation: packet.Metadata().CaptureInfo,
			Trans:              packet.TransportLayer().TransportFlow(),
			Net:                packet.NetworkLayer().NetworkFlow(),
		})
		u.streams[packet.TransportLayer().TransportFlow().FastHash()] = str
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

	// check if we already have a banner for the IP + Port combination
	service.Store.Lock()
	if serv, ok := service.Store.Items[serviceIdent]; ok {
		defer service.Store.Unlock()

		for _, f := range serv.Flows {
			if f == flowIdent {
				return
			}
		}

		serv.Flows = append(serv.Flows, flowIdent)
		return
	}
	service.Store.Unlock()

	// nope. lets create a new one
	serv := service.NewService(firstPacket.UnixNano(), serverBytes, clientBytes, net.Dst().String())
	serv.Banner = string(banner)
	serv.IP = net.Dst().String()
	serv.Port = utils.DecodePort(transport.Dst().Raw())

	// set flow ident, h.parent.ident is the client flow
	serv.Flows = []string{flowIdent}

	dst, err := strconv.Atoi(transport.Dst().String())
	if err == nil {
		serv.Protocol = "UDP"
		serv.Name = resolvers.LookupServiceByPort(dst, typeUDP)
	}

	service.MatchServiceProbes(serv, banner, flowIdent)

	// add new service
	service.Store.Lock()
	service.Store.Items[serviceIdent] = serv
	service.Store.Unlock()

	streamutils.Stats.Lock()
	streamutils.Stats.NumServices++
	streamutils.Stats.Unlock()
}

// TODO: ensure that only decoders of protocols are called that actually support being transported via UDP
// TODO: specify transport protocols during decoder creation
func (u *udpStream) decode() {
	// choose the decoder to run against the data stream
	var (
		cr               = u.data[0].Raw()
		sr               []byte
		found            bool
		serverFirstReply time.Time
	)

	// first message defines the client
	clientTransport := u.data[0].Transport()

	// search for the first server reply
	for _, d := range u.data {
		if d.Transport() != clientTransport {
			sr = d.Raw()
			serverFirstReply = d.CaptureInfo().Timestamp
			break
		}
	}

	// set directions for all fragments
	// TODO: this is a bit of a hack, since we are reusing the constants from the TCP reassembly
	// TODO: add generic stream direction types in netcap and use those in the readers Decode() implementations instead
	for _, d := range u.data {
		if d.Transport() == clientTransport {
			// client
			d.SetDirection(reassembly.TCPDirClientToServer)
		} else {
			// server
			d.SetDirection(reassembly.TCPDirServerToClient)
		}
	}

	conv := &core.ConversationInfo{
		Data:              u.data,
		Ident:             utils.CreateFlowIdentFromLayerFlows(u.data[0].Network(), u.data[0].Transport()),
		FirstClientPacket: u.data[0].CaptureInfo().Timestamp,
		FirstServerPacket: serverFirstReply,
		ClientIP:          u.data[0].Network().Src().String(),
		ServerIP:          u.data[0].Network().Dst().String(),
		ClientPort:        utils.DecodePort(u.data[0].Transport().Src().Raw()),
		ServerPort:        utils.DecodePort(u.data[0].Transport().Dst().Raw()),
	}

	// make a good first guess based on the destination port of the connection
	if sd, exists := stream.DefaultStreamDecoders[utils.DecodePort(u.data[0].Transport().Dst().Raw())]; exists {
		if sd.Transport() == core.UDP || sd.Transport() == core.All {
			if sd.GetReaderFactory() != nil && sd.CanDecodeStream(cr, sr) {
				u.decoder = sd.GetReaderFactory().New(conv)
				found = true
			}
		}
	}

	// if no stream decoder for the port was found, or the stream decoder did not match
	// try all available decoders and use the first one that matches
	if !found {
		for _, sd := range stream.DefaultStreamDecoders {
			if sd.Transport() == core.UDP || sd.Transport() == core.All {
				if sd.GetReaderFactory() != nil && sd.CanDecodeStream(cr, sr) {
					u.decoder = sd.GetReaderFactory().New(conv)
					break
				}
			}
		}
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
