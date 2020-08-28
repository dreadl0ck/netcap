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
	"github.com/dreadl0ck/netcap/logger"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/gogo/protobuf/proto"
	"github.com/mgutz/ansi"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

var udpStreams = newUDPStreamPool()

const typeUDP = "udp"

// udpData represents a udp data stream.
type udpStream struct {
	data udpDataSlice
	sync.Mutex
}

// udpData represents a data fragment received from an UDP stream.
type udpData struct {
	raw       []byte
	ci        gopacket.CaptureInfo
	net       gopacket.Flow
	transport gopacket.Flow
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

// takes a udp packet and tracks the data seen for the conversation.
func (u *udpStreamPool) handleUDP(packet gopacket.Packet, udpLayer gopacket.Layer) {
	u.Lock()
	if s, ok := u.streams[packet.TransportLayer().TransportFlow().FastHash()]; ok {
		u.Unlock()

		// update existing
		s.Lock()
		s.data = append(s.data, &udpData{
			raw:       udpLayer.LayerPayload(),
			ci:        packet.Metadata().CaptureInfo,
			transport: packet.TransportLayer().TransportFlow(),
			net:       packet.NetworkLayer().NetworkFlow(),
		})
		s.Unlock()
	} else {
		// add new
		u.streams[packet.TransportLayer().TransportFlow().FastHash()] = &udpStream{
			data: []*udpData{
				{
					raw:       udpLayer.LayerPayload(),
					ci:        packet.Metadata().CaptureInfo,
					transport: packet.TransportLayer().TransportFlow(),
					net:       packet.NetworkLayer().NetworkFlow(),
				},
			},
		}
		u.Unlock()
	}
}

var udpDecoder = newGoPacketDecoder(
	types.Type_NC_UDP,
	layers.LayerTypeUDP,
	"User Datagram Protocol (UDP) is a connectionless communications protocol, that facilitates the exchange of messages between computing devices in a network",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if udp, ok := layer.(*layers.UDP); ok {
			var payload []byte
			if conf.IncludePayloads {
				payload = layer.LayerPayload()
			}
			var e float64
			if conf.CalculateEntropy {
				e = entropy(udp.Payload)
			}

			return &types.UDP{
				Timestamp:      timestamp,
				SrcPort:        int32(udp.SrcPort),
				DstPort:        int32(udp.DstPort),
				Length:         int32(udp.Length),
				Checksum:       int32(udp.Checksum),
				PayloadEntropy: e,
				PayloadSize:    int32(len(udp.Payload)),
				Payload:        payload,
			}
		}

		return nil
	},
)

func (u *udpStreamPool) saveAllUDPConnections() {
	u.Lock()
	for _, s := range u.streams {
		s.Lock()
		sort.Sort(s.data)

		var (
			clientNetwork            gopacket.Flow
			clientTransport          gopacket.Flow
			firstPacket              time.Time
			colored                  bytes.Buffer
			raw                      bytes.Buffer
			ident                    string
			serverBytes, clientBytes int
		)

		// check who is client and who server based on first packet
		if len(s.data) > 0 {
			clientTransport = s.data[0].transport
			clientNetwork = s.data[0].net
			firstPacket = s.data[0].ci.Timestamp
			ident = filepath.Clean(fmt.Sprintf("%s-%s", clientNetwork, clientTransport))
		} else {
			// skip empty conns
			continue
		}

		var serverBanner bytes.Buffer

		for _, d := range s.data {
			if d.transport == clientTransport {
				clientBytes += len(d.raw)
				// client
				raw.Write(d.raw)
				colored.WriteString(ansi.Red)
				colored.Write(d.raw)
				colored.WriteString(ansi.Reset)
			} else {
				// server
				serverBytes += len(d.raw)
				for _, b := range d.raw {
					if serverBanner.Len() == conf.BannerSize {
						break
					}
					serverBanner.WriteByte(b)
				}
				raw.Write(d.raw)
				colored.WriteString(ansi.Blue)
				colored.Write(d.raw)
				colored.WriteString(ansi.Reset)
			}
		}
		s.Unlock()

		// save stream data
		err := saveUDPConnection(raw.Bytes(), colored.Bytes(), ident, firstPacket, clientTransport)
		if err != nil {
			fmt.Println("failed to save UDP connection:", err)
		}

		// save service banner
		saveUDPServiceBanner(serverBanner.Bytes(), ident, clientNetwork.Dst().String()+":"+clientTransport.Dst().String(), firstPacket, serverBytes, clientBytes, clientNetwork, clientTransport)
	}
	u.Unlock()
}

// saveUDPConnection saves the contents of a client server conversation via UDP to the filesystem.
func saveUDPConnection(raw []byte, colored []byte, ident string, firstPacket time.Time, transport gopacket.Flow) error {
	// prevent processing zero bytes
	if len(raw) == 0 {
		return nil
	}

	banner := runHarvesters(raw, transport, ident, firstPacket)

	if !conf.SaveConns {
		return nil
	}

	// fmt.Println("save connection", ident, len(raw), len(colored))
	// fmt.Println(string(colored))

	var (
		typ = getServiceName(banner, transport)

		// path for storing the data
		root = filepath.Join(conf.Out, "udpConnections", typ)

		// file basename
		base = filepath.Clean(path.Base(ident)) + binaryFileExtension
	)

	// make sure root path exists
	err := os.MkdirAll(root, defaults.DirectoryPermission)
	if err != nil {
		logger.DebugLog.Println("failed to create directory:", root, defaults.DirectoryPermission)
	}
	base = path.Join(root, base)

	logger.ReassemblyLog.Println("saveConnection", base)

	stats.Lock()
	stats.savedUDPConnections++
	stats.Unlock()

	// append to files
	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, defaults.FilePermission)
	if err != nil {
		logReassemblyError("UDP connection create", "Cannot create %s: %s\n", base, err)

		return err
	}

	// do not colorize the data written to disk if its just a single keepalive byte
	if len(raw) == 1 {
		colored = raw
	}

	// save the colored version
	// assign a new buffer
	r := bytes.NewBuffer(colored)
	w, err := io.Copy(f, r)
	if err != nil {
		logReassemblyError("UDP stream", "%s: failed to save UDP connection %s (l:%d): %s\n", ident, base, w, err)
	} else {
		logReassemblyInfo("%s: Saved UDP connection %s (l:%d)\n", ident, base, w)
	}

	err = f.Close()
	if err != nil {
		logReassemblyError("UDP connection", "%s: failed to close UDP connection file %s (l:%d): %s\n", ident, base, w, err)
	}

	return nil
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
	serv.Port = transport.Dst().String()

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
