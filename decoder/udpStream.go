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

package decoder

import (
	"bytes"
	"fmt"
	"sort"
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
	data dataFragments
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

// TODO: currently this is only called on teardown. implement flushing continuously.
// TODO: parallelize
func (u *udpStreamPool) saveAllUDPConnections() {
	u.Lock()
	for i, s := range u.streams {

		fmt.Println(i, "/", len(u.streams))
		s.Lock()
		sort.Sort(s.data)

		var (
			clientNetwork            gopacket.Flow
			clientTransport          gopacket.Flow
			firstPacket              time.Time
			ident                    string
			serverBytes, clientBytes int
		)

		// check who is client and who server based on first packet
		if len(s.data) > 0 {
			clientTransport = s.data[0].transport()
			clientNetwork = s.data[0].network()
			firstPacket = s.data[0].captureInfo().Timestamp
			ident = utils.CreateFlowIdentFromLayerFlows(clientNetwork, clientTransport)
		} else {
			// skip empty conns
			continue
		}

		var serverBanner bytes.Buffer

		for _, d := range s.data {
			if d.transport() == clientTransport {
				clientBytes += len(d.raw())
			} else {
				// server
				serverBytes += len(d.raw())
				for _, b := range d.raw() {
					if serverBanner.Len() == conf.BannerSize {
						break
					}
					serverBanner.WriteByte(b)
				}
			}
		}
		s.Unlock()

		// TODO: call UDP stream decoders

		// save stream data
		err := saveConversation(protoUDP, s.data, ident, firstPacket, clientTransport)
		if err != nil {
			fmt.Println("failed to save UDP conversation:", err)
		}

		// save service banner
		saveUDPServiceBanner(serverBanner.Bytes(), ident, clientNetwork.Dst().String()+":"+clientTransport.Dst().String(), firstPacket, serverBytes, clientBytes, clientNetwork, clientTransport)
	}
	u.Unlock()
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
