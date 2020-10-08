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

package stream

import (
	"github.com/dreadl0ck/netcap/reassembly"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/dreadl0ck/gopacket"

	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

var udpStreams = newUDPStreamPool()

const typeUDP = "udp"

// udpData represents a udp data stream.
type udpStream struct {
	data    dataFragments
	decoder streamDecoder
	sync.Mutex
}

// udpStreamPool holds a pool of UDP streams.
type udpStreamPool struct {
	streams map[uint64]*udpStream
	sync.Mutex
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

// takes an UDP packet and tracks the data seen for the conversation.
func (u *udpStreamPool) handleUDP(packet gopacket.Packet, udpLayer gopacket.Layer) {
	u.Lock()
	if s, ok := u.streams[packet.TransportLayer().TransportFlow().FastHash()]; ok {
		u.Unlock()

		// update existing
		s.Lock()
		s.data = append(s.data, &streamData{
			rawData: udpLayer.LayerPayload(),
			ci:      packet.Metadata().CaptureInfo,
			trans:   packet.TransportLayer().TransportFlow(),
			net:     packet.NetworkLayer().NetworkFlow(),
		})
		s.Unlock()
	} else {
		// add new
		stream := new(udpStream)
		stream.data = append(stream.data, &streamData{
			rawData: udpLayer.LayerPayload(),
			ci:      packet.Metadata().CaptureInfo,
			trans:   packet.TransportLayer().TransportFlow(),
			net:     packet.NetworkLayer().NetworkFlow(),
		})
		u.streams[packet.TransportLayer().TransportFlow().FastHash()] = stream
		u.Unlock()
	}
}

// saves the banner for a UDP service to the filesystem
// and limits the length of the saved data to the BannerSize value from the config.
func saveUDPServiceBanner(banner []byte, flowIdent string, serviceIdent string, firstPacket time.Time, serverBytes int, clientBytes int, net gopacket.Flow, transport gopacket.Flow) {
	// limit length of data
	if len(banner) >= conf.BannerSize {
		banner = banner[:conf.BannerSize]
	}

	// check if we already have a banner for the IP + Port combination
	ServiceStore.Lock()
	if serv, ok := ServiceStore.Items[serviceIdent]; ok {
		defer ServiceStore.Unlock()

		for _, f := range serv.Flows {
			if f == flowIdent {
				return
			}
		}

		serv.Flows = append(serv.Flows, flowIdent)
		return
	}
	ServiceStore.Unlock()

	// nope. lets create a new one
	serv := newService(firstPacket.UnixNano(), serverBytes, clientBytes, net.Dst().String())
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

	matchServiceProbes(serv, banner, flowIdent)

	// add new service
	ServiceStore.Lock()
	ServiceStore.Items[serviceIdent] = serv
	ServiceStore.Unlock()

	stats.Lock()
	stats.numServices++
	stats.Unlock()
}

// TODO: ensure that only decoders of protocols are called that actually support being transported via UDP
// TODO: specify transport protocols during decoder creation
func (u *udpStream) decode() {

	// choose the decoder to run against the data stream
	var (
		cr               = u.data[0].raw()
		sr               []byte
		found            bool
		serverFirstReply time.Time
	)

	// first message defines the client
	clientTransport := u.data[0].transport()

	// search for the first server reply
	for _, d := range u.data {
		if d.transport() != clientTransport {
			sr = d.raw()
			serverFirstReply = d.captureInfo().Timestamp
			break
		}
	}

	// set directions for all fragments
	// TODO: this is a bit of a hack, since we are reusing the constants from the TCP reassembly
	// TODO: add generic stream direction types in netcap and use those in the readers Decode() implementations instead
	for _, d := range u.data {
		if d.transport() == clientTransport {
			// client
			d.setDirection(reassembly.TCPDirClientToServer)
		} else {
			// server
			d.setDirection(reassembly.TCPDirServerToClient)
		}
	}

	conv := &conversationInfo{
		data:              u.data,
		ident:             utils.CreateFlowIdentFromLayerFlows(u.data[0].network(), u.data[0].transport()),
		firstClientPacket: u.data[0].captureInfo().Timestamp,
		firstServerPacket: serverFirstReply,
		clientIP:          u.data[0].network().Src().String(),
		serverIP:          u.data[0].network().Dst().String(),
		clientPort:        utils.DecodePort(u.data[0].transport().Src().Raw()),
		serverPort:        utils.DecodePort(u.data[0].transport().Dst().Raw()),
	}

	// make a good first guess based on the destination port of the connection
	if sd, exists := defaultStreamDecoders[utils.DecodePort(u.data[0].transport().Dst().Raw())]; exists {
		if sd.GetReaderFactory() != nil && sd.CanDecode(cr, sr) {
			u.decoder = sd.GetReaderFactory().New(conv)
			found = true
		}
	}

	// if no stream decoder for the port was found, or the stream decoder did not match
	// try all available decoders and use the first one that matches
	if !found {
		for _, sd := range defaultStreamDecoders {
			if sd.GetReaderFactory() != nil && sd.CanDecode(cr, sr) {
				u.decoder = sd.GetReaderFactory().New(conv)
				break
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
